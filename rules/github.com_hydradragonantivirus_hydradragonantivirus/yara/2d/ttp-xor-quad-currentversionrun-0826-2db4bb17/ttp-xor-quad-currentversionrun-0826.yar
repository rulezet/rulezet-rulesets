rule TTP_XOR_QUAD_CurrentVersionRun_0826 {
  strings:
    $key_0826 = { 5b 49 [2] 7f 47 [2] 54 6b [2] 7a 49 [2] 6e 52 [2] 61 48 [2] 7f 55 [2] 7d 54 [2] 66 52 [2] 7a 55 [2] 66 7a }

  condition:
    any of them
}