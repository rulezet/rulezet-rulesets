rule TTP_XOR_QUAD_CurrentVersionRun_558c {
  strings:
    $key_558c = { 06 e3 [2] 22 ed [2] 09 c1 [2] 27 e3 [2] 33 f8 [2] 3c e2 [2] 22 ff [2] 20 fe [2] 3b f8 [2] 27 ff [2] 3b d0 }

  condition:
    any of them
}