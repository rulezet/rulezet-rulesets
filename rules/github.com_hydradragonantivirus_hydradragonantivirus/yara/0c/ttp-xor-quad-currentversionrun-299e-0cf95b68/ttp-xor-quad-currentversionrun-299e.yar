rule TTP_XOR_QUAD_CurrentVersionRun_299e {
  strings:
    $key_299e = { 7a f1 [2] 5e ff [2] 75 d3 [2] 5b f1 [2] 4f ea [2] 40 f0 [2] 5e ed [2] 5c ec [2] 47 ea [2] 5b ed [2] 47 c2 }

  condition:
    any of them
}