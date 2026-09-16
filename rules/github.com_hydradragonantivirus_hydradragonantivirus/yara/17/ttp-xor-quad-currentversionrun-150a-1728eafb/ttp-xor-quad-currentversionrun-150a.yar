rule TTP_XOR_QUAD_CurrentVersionRun_150a {
  strings:
    $key_150a = { 46 65 [2] 62 6b [2] 49 47 [2] 67 65 [2] 73 7e [2] 7c 64 [2] 62 79 [2] 60 78 [2] 7b 7e [2] 67 79 [2] 7b 56 }

  condition:
    any of them
}