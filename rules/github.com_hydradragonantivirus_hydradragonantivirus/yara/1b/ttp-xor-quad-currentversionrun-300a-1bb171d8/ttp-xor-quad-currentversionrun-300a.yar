rule TTP_XOR_QUAD_CurrentVersionRun_300a {
  strings:
    $key_300a = { 63 65 [2] 47 6b [2] 6c 47 [2] 42 65 [2] 56 7e [2] 59 64 [2] 47 79 [2] 45 78 [2] 5e 7e [2] 42 79 [2] 5e 56 }

  condition:
    any of them
}