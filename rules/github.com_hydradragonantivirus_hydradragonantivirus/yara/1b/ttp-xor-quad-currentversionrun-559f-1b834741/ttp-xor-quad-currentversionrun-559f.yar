rule TTP_XOR_QUAD_CurrentVersionRun_559f {
  strings:
    $key_559f = { 06 f0 [2] 22 fe [2] 09 d2 [2] 27 f0 [2] 33 eb [2] 3c f1 [2] 22 ec [2] 20 ed [2] 3b eb [2] 27 ec [2] 3b c3 }

  condition:
    any of them
}