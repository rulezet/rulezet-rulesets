rule TTP_XOR_QUAD_CurrentVersionRun_0e9f {
  strings:
    $key_0e9f = { 5d f0 [2] 79 fe [2] 52 d2 [2] 7c f0 [2] 68 eb [2] 67 f1 [2] 79 ec [2] 7b ed [2] 60 eb [2] 7c ec [2] 60 c3 }

  condition:
    any of them
}