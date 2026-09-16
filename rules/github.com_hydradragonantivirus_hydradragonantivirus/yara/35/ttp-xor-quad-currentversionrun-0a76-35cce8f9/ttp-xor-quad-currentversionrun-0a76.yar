rule TTP_XOR_QUAD_CurrentVersionRun_0a76 {
  strings:
    $key_0a76 = { 59 19 [2] 7d 17 [2] 56 3b [2] 78 19 [2] 6c 02 [2] 63 18 [2] 7d 05 [2] 7f 04 [2] 64 02 [2] 78 05 [2] 64 2a }

  condition:
    any of them
}