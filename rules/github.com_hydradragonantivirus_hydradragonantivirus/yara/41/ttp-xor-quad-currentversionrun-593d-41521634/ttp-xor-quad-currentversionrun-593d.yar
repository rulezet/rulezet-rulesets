rule TTP_XOR_QUAD_CurrentVersionRun_593d {
  strings:
    $key_593d = { 0a 52 [2] 2e 5c [2] 05 70 [2] 2b 52 [2] 3f 49 [2] 30 53 [2] 2e 4e [2] 2c 4f [2] 37 49 [2] 2b 4e [2] 37 61 }

  condition:
    any of them
}