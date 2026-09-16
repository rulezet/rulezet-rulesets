rule TTP_XOR_QUAD_CurrentVersionRun_358d {
  strings:
    $key_358d = { 66 e2 [2] 42 ec [2] 69 c0 [2] 47 e2 [2] 53 f9 [2] 5c e3 [2] 42 fe [2] 40 ff [2] 5b f9 [2] 47 fe [2] 5b d1 }

  condition:
    any of them
}