rule TTP_XOR_QUAD_CurrentVersionRun_e09f {
  strings:
    $key_e09f = { b3 f0 [2] 97 fe [2] bc d2 [2] 92 f0 [2] 86 eb [2] 89 f1 [2] 97 ec [2] 95 ed [2] 8e eb [2] 92 ec [2] 8e c3 }

  condition:
    any of them
}