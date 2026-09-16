rule TTP_XOR_QUAD_CurrentVersionRun_050a {
  strings:
    $key_050a = { 56 65 [2] 72 6b [2] 59 47 [2] 77 65 [2] 63 7e [2] 6c 64 [2] 72 79 [2] 70 78 [2] 6b 7e [2] 77 79 [2] 6b 56 }

  condition:
    any of them
}