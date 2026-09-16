rule TTP_XOR_QUAD_CurrentVersionRun_178c {
  strings:
    $key_178c = { 44 e3 [2] 60 ed [2] 4b c1 [2] 65 e3 [2] 71 f8 [2] 7e e2 [2] 60 ff [2] 62 fe [2] 79 f8 [2] 65 ff [2] 79 d0 }

  condition:
    any of them
}