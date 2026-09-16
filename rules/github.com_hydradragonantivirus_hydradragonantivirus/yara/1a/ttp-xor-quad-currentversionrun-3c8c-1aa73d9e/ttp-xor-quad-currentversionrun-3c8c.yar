rule TTP_XOR_QUAD_CurrentVersionRun_3c8c {
  strings:
    $key_3c8c = { 6f e3 [2] 4b ed [2] 60 c1 [2] 4e e3 [2] 5a f8 [2] 55 e2 [2] 4b ff [2] 49 fe [2] 52 f8 [2] 4e ff [2] 52 d0 }

  condition:
    any of them
}