rule TTP_XOR_QUAD_CurrentVersionRun_f69f {
  strings:
    $key_f69f = { a5 f0 [2] 81 fe [2] aa d2 [2] 84 f0 [2] 90 eb [2] 9f f1 [2] 81 ec [2] 83 ed [2] 98 eb [2] 84 ec [2] 98 c3 }

  condition:
    any of them
}