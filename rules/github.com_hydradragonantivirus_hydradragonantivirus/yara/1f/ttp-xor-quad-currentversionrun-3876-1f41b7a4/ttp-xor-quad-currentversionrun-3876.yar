rule TTP_XOR_QUAD_CurrentVersionRun_3876 {
  strings:
    $key_3876 = { 6b 19 [2] 4f 17 [2] 64 3b [2] 4a 19 [2] 5e 02 [2] 51 18 [2] 4f 05 [2] 4d 04 [2] 56 02 [2] 4a 05 [2] 56 2a }

  condition:
    any of them
}