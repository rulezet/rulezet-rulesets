rule TTP_XOR_QUAD_CurrentVersionRun_e291 {
  strings:
    $key_e291 = { b1 fe [2] 95 f0 [2] be dc [2] 90 fe [2] 84 e5 [2] 8b ff [2] 95 e2 [2] 97 e3 [2] 8c e5 [2] 90 e2 [2] 8c cd }

  condition:
    any of them
}