rule TTP_XOR_QUAD_CurrentVersionRun_0766 {
  strings:
    $key_0766 = { 54 09 [2] 70 07 [2] 5b 2b [2] 75 09 [2] 61 12 [2] 6e 08 [2] 70 15 [2] 72 14 [2] 69 12 [2] 75 15 [2] 69 3a }

  condition:
    any of them
}