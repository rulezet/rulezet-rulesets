rule TTP_XOR_QUAD_CurrentVersionRun_3091 {
  strings:
    $key_3091 = { 63 fe [2] 47 f0 [2] 6c dc [2] 42 fe [2] 56 e5 [2] 59 ff [2] 47 e2 [2] 45 e3 [2] 5e e5 [2] 42 e2 [2] 5e cd }

  condition:
    any of them
}