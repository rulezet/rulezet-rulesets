rule TTP_XOR_QUAD_CurrentVersionRun_120a {
  strings:
    $key_120a = { 41 65 [2] 65 6b [2] 4e 47 [2] 60 65 [2] 74 7e [2] 7b 64 [2] 65 79 [2] 67 78 [2] 7c 7e [2] 60 79 [2] 7c 56 }

  condition:
    any of them
}