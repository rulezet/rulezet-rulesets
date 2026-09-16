rule TTP_XOR_QUAD_CurrentVersionRun_370a {
  strings:
    $key_370a = { 64 65 [2] 40 6b [2] 6b 47 [2] 45 65 [2] 51 7e [2] 5e 64 [2] 40 79 [2] 42 78 [2] 59 7e [2] 45 79 [2] 59 56 }

  condition:
    any of them
}