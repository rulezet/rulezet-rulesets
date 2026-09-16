rule Trojan_Hooker_Gen_Variant_Zusy_553604 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Gen.Variant.Zusy.553604.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61b2402aeaaba836be0cb3f9e3eae72a20c60ae531ba18ec64c40f266419c242"

  strings:
    $s1  = "Access to remote file \"%s\" is password protected." fullword wide
    $s2  = "acHTTP component (AppControls.com)" fullword ascii
    $s3  = "Tempo estimado: %d:%.2d:%.2d" fullword wide
    $s4  = "ncia: %.1f Kb/s%Tempo restante estimado: %d:%.2d:%.2d" fullword wide
    $s5  = " di trasferimento: %.1f Kb/s#Tempo residuo stimato: %d:%.2d:%.2d" fullword wide
    $s6  = "ncia: %.1f Kb/s#Temps estimat restant: %d:%.2d:%.2d" fullword wide
    $s7  = "Downloading %d of %dZThe update of %s has been successfully completed." fullword wide
    $s8  = "using most recent version of this program.JFile which contains upgrade information was not found on developer's site.iHost %s un" wide
    $s9  = "Please enter your username and password (received after registration) to continue software upgrade.lConnection with remote serve" wide
    $s10 = "die aktuellste Version dieser Anwendung.MDatei mit Upgrade Informationen wurde auf der Herstellerseite nicht gefunden.iHost %s u" wide
    $s11 = "Akses ke remot file \"%s\" Terlindung password." fullword wide
    $s12 = " Failed to delete tab at index %d\"Failed to retrieve tab at index %d Failed to get object at index %d\"Failed to set tab \"%s\"" wide
    $s13 = "tzt. Bitte geben Sie Ihren Benutzernamen und Ihr Passwort ein (erhalten Sie nach der Registrierung), um mit dem Upgrade fortzufa" wide
    $s14 = "Downloaden %d van %dTDe upgrade van %s is succesvol voltooid." fullword wide
    $s15 = "rbereder. . .bEn nyare version av %s har givits ut." fullword wide
    $s16 = "Insira a password" fullword wide
    $s17 = "Por favor introduza a sua password (recebida depois de registado) para continuar o upgrade do software.[Liga" fullword wide
    $s18 = "Host %s non raggiungibile." fullword wide
    $s19 = " protetto da password." fullword wide
    $s20 = "Per favore inserisci il tuo nome utente e la password (ricevuta dopo la registrazione) per continuare l' aggiornamento del softw" wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}