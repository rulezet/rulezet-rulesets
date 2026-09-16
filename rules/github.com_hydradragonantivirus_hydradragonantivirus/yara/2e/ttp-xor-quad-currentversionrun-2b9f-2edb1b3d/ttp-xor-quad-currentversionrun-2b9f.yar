rule TTP_XOR_QUAD_CurrentVersionRun_2b9f {
  strings:
    $key_2b9f = { 78 f0 [2] 5c fe [2] 77 d2 [2] 59 f0 [2] 4d eb [2] 42 f1 [2] 5c ec [2] 5e ed [2] 45 eb [2] 59 ec [2] 45 c3 }

  condition:
    any of them
}