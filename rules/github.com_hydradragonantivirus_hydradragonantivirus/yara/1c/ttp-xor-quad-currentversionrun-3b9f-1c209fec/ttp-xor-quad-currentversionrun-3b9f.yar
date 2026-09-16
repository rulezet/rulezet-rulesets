rule TTP_XOR_QUAD_CurrentVersionRun_3b9f {
  strings:
    $key_3b9f = { 68 f0 [2] 4c fe [2] 67 d2 [2] 49 f0 [2] 5d eb [2] 52 f1 [2] 4c ec [2] 4e ed [2] 55 eb [2] 49 ec [2] 55 c3 }

  condition:
    any of them
}