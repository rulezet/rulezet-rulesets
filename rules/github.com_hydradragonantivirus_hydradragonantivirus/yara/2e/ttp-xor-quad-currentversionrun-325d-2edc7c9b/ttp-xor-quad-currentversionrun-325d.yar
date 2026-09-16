rule TTP_XOR_QUAD_CurrentVersionRun_325d {
  strings:
    $key_325d = { 61 32 [2] 45 3c [2] 6e 10 [2] 40 32 [2] 54 29 [2] 5b 33 [2] 45 2e [2] 47 2f [2] 5c 29 [2] 40 2e [2] 5c 01 }

  condition:
    any of them
}