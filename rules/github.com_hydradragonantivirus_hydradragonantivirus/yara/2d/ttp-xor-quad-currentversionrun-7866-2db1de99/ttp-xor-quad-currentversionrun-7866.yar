rule TTP_XOR_QUAD_CurrentVersionRun_7866 {
  strings:
    $key_7866 = { 2b 09 [2] 0f 07 [2] 24 2b [2] 0a 09 [2] 1e 12 [2] 11 08 [2] 0f 15 [2] 0d 14 [2] 16 12 [2] 0a 15 [2] 16 3a }

  condition:
    any of them
}