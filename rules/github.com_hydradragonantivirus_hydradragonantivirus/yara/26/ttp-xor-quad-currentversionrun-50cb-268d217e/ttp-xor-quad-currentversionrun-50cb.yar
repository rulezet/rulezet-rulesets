rule TTP_XOR_QUAD_CurrentVersionRun_50cb {
  strings:
    $key_50cb = { 03 a4 [2] 27 aa [2] 0c 86 [2] 22 a4 [2] 36 bf [2] 39 a5 [2] 27 b8 [2] 25 b9 [2] 3e bf [2] 22 b8 [2] 3e 97 }

  condition:
    any of them
}