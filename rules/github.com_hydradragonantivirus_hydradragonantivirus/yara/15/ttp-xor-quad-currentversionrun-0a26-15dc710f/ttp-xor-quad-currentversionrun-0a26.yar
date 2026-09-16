rule TTP_XOR_QUAD_CurrentVersionRun_0a26 {
  strings:
    $key_0a26 = { 59 49 [2] 7d 47 [2] 56 6b [2] 78 49 [2] 6c 52 [2] 63 48 [2] 7d 55 [2] 7f 54 [2] 64 52 [2] 78 55 [2] 64 7a }

  condition:
    any of them
}