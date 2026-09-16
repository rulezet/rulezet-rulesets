rule TTP_XOR_QUAD_CurrentVersionRun_099e {
  strings:
    $key_099e = { 5a f1 [2] 7e ff [2] 55 d3 [2] 7b f1 [2] 6f ea [2] 60 f0 [2] 7e ed [2] 7c ec [2] 67 ea [2] 7b ed [2] 67 c2 }

  condition:
    any of them
}