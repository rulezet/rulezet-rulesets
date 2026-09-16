rule TTP_XOR_MULT_DOSStub_e94c {
  strings:
    $key_e94c = { bd 24 [2] c9 3c [2] 8e 3e [2] c9 2f [2] 87 23 [2] 8b 29 [2] 9c 22 [2] 87 6c [2] ba }

  condition:
    any of them
}