rule TTP_XOR_MULT_DOSStub_daed {
  strings:
    $key_daed = { 8e 85 [2] fa 9d [2] bd 9f [2] fa 8e [2] b4 82 [2] b8 88 [2] af 83 [2] b4 cd [2] 89 }

  condition:
    any of them
}