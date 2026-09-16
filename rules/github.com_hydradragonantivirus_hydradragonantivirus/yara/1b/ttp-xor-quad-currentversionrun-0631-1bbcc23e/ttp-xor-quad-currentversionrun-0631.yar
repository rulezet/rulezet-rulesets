rule TTP_XOR_QUAD_CurrentVersionRun_0631 {
  strings:
    $key_0631 = { 55 5e [2] 71 50 [2] 5a 7c [2] 74 5e [2] 60 45 [2] 6f 5f [2] 71 42 [2] 73 43 [2] 68 45 [2] 74 42 [2] 68 6d }

  condition:
    any of them
}