rule TTP_XOR_QUAD_CurrentVersionRun_0927 {
  strings:
    $key_0927 = { 5a 48 [2] 7e 46 [2] 55 6a [2] 7b 48 [2] 6f 53 [2] 60 49 [2] 7e 54 [2] 7c 55 [2] 67 53 [2] 7b 54 [2] 67 7b }

  condition:
    any of them
}