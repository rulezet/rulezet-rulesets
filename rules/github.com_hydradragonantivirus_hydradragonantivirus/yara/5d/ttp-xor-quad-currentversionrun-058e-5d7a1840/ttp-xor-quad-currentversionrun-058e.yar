rule TTP_XOR_QUAD_CurrentVersionRun_058e {
  strings:
    $key_058e = { 56 e1 [2] 72 ef [2] 59 c3 [2] 77 e1 [2] 63 fa [2] 6c e0 [2] 72 fd [2] 70 fc [2] 6b fa [2] 77 fd [2] 6b d2 }

  condition:
    any of them
}