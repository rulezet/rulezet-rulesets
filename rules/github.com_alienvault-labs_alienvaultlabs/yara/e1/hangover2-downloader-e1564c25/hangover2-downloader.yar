rule Hangover2_Downloader {

  strings:

    $a = "WinInetGet/0.1" wide ascii

    $b = "Excep while up" wide ascii

    $c = "&file=" wide ascii

    $d = "&str=" wide ascii

    $e = "?cn=" wide ascii

  condition:

    all of them
}