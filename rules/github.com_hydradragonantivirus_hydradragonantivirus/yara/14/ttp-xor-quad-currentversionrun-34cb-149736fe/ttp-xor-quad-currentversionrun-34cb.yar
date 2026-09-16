rule TTP_XOR_QUAD_CurrentVersionRun_34cb {
  strings:
    $key_34cb = { 67 a4 [2] 43 aa [2] 68 86 [2] 46 a4 [2] 52 bf [2] 5d a5 [2] 43 b8 [2] 41 b9 [2] 5a bf [2] 46 b8 [2] 5a 97 }

  condition:
    any of them
}