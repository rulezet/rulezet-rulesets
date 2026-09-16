rule TTP_XOR_QUAD_CurrentVersionRun_4e9f {
  strings:
    $key_4e9f = { 1d f0 [2] 39 fe [2] 12 d2 [2] 3c f0 [2] 28 eb [2] 27 f1 [2] 39 ec [2] 3b ed [2] 20 eb [2] 3c ec [2] 20 c3 }

  condition:
    any of them
}