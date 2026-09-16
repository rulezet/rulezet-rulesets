rule TTP_XOR_QUAD_CurrentVersionRun_0866 {
  strings:
    $key_0866 = { 5b 09 [2] 7f 07 [2] 54 2b [2] 7a 09 [2] 6e 12 [2] 61 08 [2] 7f 15 [2] 7d 14 [2] 66 12 [2] 7a 15 [2] 66 3a }

  condition:
    any of them
}