rule TTP_XOR_QUAD_CurrentVersionRun_3866 {
  strings:
    $key_3866 = { 6b 09 [2] 4f 07 [2] 64 2b [2] 4a 09 [2] 5e 12 [2] 51 08 [2] 4f 15 [2] 4d 14 [2] 56 12 [2] 4a 15 [2] 56 3a }

  condition:
    any of them
}