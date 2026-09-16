rule TTP_XOR_QUAD_CurrentVersionRun_30fa {
  strings:
    $key_30fa = { 63 95 [2] 47 9b [2] 6c b7 [2] 42 95 [2] 56 8e [2] 59 94 [2] 47 89 [2] 45 88 [2] 5e 8e [2] 42 89 [2] 5e a6 }

  condition:
    any of them
}