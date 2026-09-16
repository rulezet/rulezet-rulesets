rule TTP_XOR_QUAD_CurrentVersionRun_fe8c {
  strings:
    $key_fe8c = { ad e3 [2] 89 ed [2] a2 c1 [2] 8c e3 [2] 98 f8 [2] 97 e2 [2] 89 ff [2] 8b fe [2] 90 f8 [2] 8c ff [2] 90 d0 }

  condition:
    any of them
}