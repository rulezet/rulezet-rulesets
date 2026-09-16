rule TTP_XOR_QUAD_CurrentVersionRun_0a2a {
  strings:
    $key_0a2a = { 59 45 [2] 7d 4b [2] 56 67 [2] 78 45 [2] 6c 5e [2] 63 44 [2] 7d 59 [2] 7f 58 [2] 64 5e [2] 78 59 [2] 64 76 }

  condition:
    any of them
}