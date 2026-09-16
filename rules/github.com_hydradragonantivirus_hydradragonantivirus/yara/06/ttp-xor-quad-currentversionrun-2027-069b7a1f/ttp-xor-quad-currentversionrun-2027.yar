rule TTP_XOR_QUAD_CurrentVersionRun_2027 {
  strings:
    $key_2027 = { 73 48 [2] 57 46 [2] 7c 6a [2] 52 48 [2] 46 53 [2] 49 49 [2] 57 54 [2] 55 55 [2] 4e 53 [2] 52 54 [2] 4e 7b }

  condition:
    any of them
}