rule TTP_XOR_QUAD_CurrentVersionRun_0221 {
  strings:
    $key_0221 = { 51 4e [2] 75 40 [2] 5e 6c [2] 70 4e [2] 64 55 [2] 6b 4f [2] 75 52 [2] 77 53 [2] 6c 55 [2] 70 52 [2] 6c 7d }

  condition:
    any of them
}