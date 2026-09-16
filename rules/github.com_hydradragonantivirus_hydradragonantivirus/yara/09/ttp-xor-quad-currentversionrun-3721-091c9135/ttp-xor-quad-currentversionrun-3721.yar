rule TTP_XOR_QUAD_CurrentVersionRun_3721 {
  strings:
    $key_3721 = { 64 4e [2] 40 40 [2] 6b 6c [2] 45 4e [2] 51 55 [2] 5e 4f [2] 40 52 [2] 42 53 [2] 59 55 [2] 45 52 [2] 59 7d }

  condition:
    any of them
}