rule TTP_XOR_QUAD_CurrentVersionRun_ffcb {
  strings:
    $key_ffcb = { ac a4 [2] 88 aa [2] a3 86 [2] 8d a4 [2] 99 bf [2] 96 a5 [2] 88 b8 [2] 8a b9 [2] 91 bf [2] 8d b8 [2] 91 97 }

  condition:
    any of them
}