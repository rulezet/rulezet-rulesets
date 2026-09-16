rule TTP_XOR_QUAD_CurrentVersionRun_ed9f {
  strings:
    $key_ed9f = { be f0 [2] 9a fe [2] b1 d2 [2] 9f f0 [2] 8b eb [2] 84 f1 [2] 9a ec [2] 98 ed [2] 83 eb [2] 9f ec [2] 83 c3 }

  condition:
    any of them
}