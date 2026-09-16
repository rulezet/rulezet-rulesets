rule TTP_XOR_QUAD_CurrentVersionRun_2431 {
  strings:
    $key_2431 = { 77 5e [2] 53 50 [2] 78 7c [2] 56 5e [2] 42 45 [2] 4d 5f [2] 53 42 [2] 51 43 [2] 4a 45 [2] 56 42 [2] 4a 6d }

  condition:
    any of them
}