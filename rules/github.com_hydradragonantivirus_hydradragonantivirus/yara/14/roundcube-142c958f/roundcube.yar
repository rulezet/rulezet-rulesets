import "hash"
rule Roundcube {
  condition:
    
    hash.sha1(0, filesize) == "afab52649172b46f64301f41371d346297046af2" or      hash.sha1(0, filesize) == "e6b81834e081cc2bd38fce787c5088e63d933953" or      hash.sha1(0, filesize) == "7783e9fad144ca5292630d459bd86ec5ea5894fc" or  
    
    hash.sha1(0, filesize) == "76d55f05f2070f471ba977b5b0f690c91fa8cdab" or      hash.sha1(0, filesize) == "c68319e3e1adcd3e22cf2338bc79f12fd54f6d4a"  }