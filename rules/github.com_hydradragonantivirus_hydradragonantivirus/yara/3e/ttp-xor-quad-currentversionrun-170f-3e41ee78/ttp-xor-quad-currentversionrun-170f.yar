rule TTP_XOR_QUAD_CurrentVersionRun_170f {
  strings:
    $key_170f = { 44 60 [2] 60 6e [2] 4b 42 [2] 65 60 [2] 71 7b [2] 7e 61 [2] 60 7c [2] 62 7d [2] 79 7b [2] 65 7c [2] 79 53 }

  condition:
    any of them
}