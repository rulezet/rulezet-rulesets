rule TTP_XOR_QUAD_CurrentVersionRun_051d {
  strings:
    $key_051d = { 56 72 [2] 72 7c [2] 59 50 [2] 77 72 [2] 63 69 [2] 6c 73 [2] 72 6e [2] 70 6f [2] 6b 69 [2] 77 6e [2] 6b 41 }

  condition:
    any of them
}