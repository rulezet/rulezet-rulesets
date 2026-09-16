rule TTP_XOR_QUAD_CurrentVersionRun_ee9f {
  strings:
    $key_ee9f = { bd f0 [2] 99 fe [2] b2 d2 [2] 9c f0 [2] 88 eb [2] 87 f1 [2] 99 ec [2] 9b ed [2] 80 eb [2] 9c ec [2] 80 c3 }

  condition:
    any of them
}