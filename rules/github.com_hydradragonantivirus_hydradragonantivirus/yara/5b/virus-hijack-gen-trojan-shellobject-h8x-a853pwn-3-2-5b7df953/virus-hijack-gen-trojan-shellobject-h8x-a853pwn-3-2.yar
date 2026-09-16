rule Virus_Hijack_Gen_Trojan_ShellObject_h8X_a853Pwn_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8X@a853Pwn_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d716cdce65dfd400b1c2fe2585aabb8c4aa0bcda065ead57f68b8e37cb83c364"

  strings:
    $x1  = " in corso la migrazione degli stati delle caratteristiche dalle applicazioni correlate...Applicazione: [1]MoveFilesSpostamento d" ascii
    $s2  = " necessario riavviare il computer.Impossibile registrare il modulo [2]. HRESULT [3]. Contattare il personale di supporto.Impossi" ascii
    $s3  = " necessario caricare la dll per questa operazione. Verificare che la dll si trovi nella directory SUPPORTDIR.Errore durante la c" ascii
    $s4  = " terminata. Consultare i requisiti minimi di sistema all'indirizzo http://www.adobe.com/go/reader_system_reqs_it. OLE_VERB_OPEN&" ascii
    $s5  = "port/main.htmlARPURLUPDATEINFOhttp://helpx.adobe.com/it/reader.htmlAcroIEHelper_DescriptionSupporto di collegamento per Adobe PD" ascii
    $s6  = " terminato.ISLANGFLAGITAISSCRIPT_VERSION_MISSINGIl modulo InstallScript manca nel computer.  Se disponibile, eseguire ISScript.m" ascii
    $s7  = " diffuse piattaforme desktop e mobili.ReadmeHtmlUNKNOWNPROCESSWITHIDProcesso sconosciuto con ID processo: %dInstallShieldTempPro" ascii
    $s8  = " troppo piccolo.Accesso negato. Controllare i diritti amministrativi.Computer non valido.Errore sconosciuto restituito da NetAPI" ascii
    $s9  = " necessario aver installato Microsoft(R) .NET Framework.Impossibile eseguire il file script SQL [2]. Connessione non aperta: [3]" ascii
    $s10 = "_ChkBox_Win10Imposta [BrandName] come visualizzatore predefinito per sfogliare e visualizzare i file in anteprimaPROCESSPATHWITH" ascii
    $s11 = " Microsoft SQL Server Desktop Engine o SQL Server Express.Errore durante il recupero della versione dello schema da [2] '[3]'. D" ascii
    $s12 = "nella directory TEMP dell'utente.ISNetAPI.dll non " fullword ascii
    $s13 = " diffuse piattaforme desktop e mobili.ReadmeHtmlUNKNOWNPROCESSWITHIDProcesso sconosciuto con ID processo: %dInstallShieldTempPro" ascii
    $s14 = " necessario specificare il nome utente nel formato DOMINIO\\Nomeutente.Errore durante il caricamento o la creazione del file INI" ascii
    $s15 = " un messaggio di trasferimentocaRemoveVRootsARPREADMELeggimi.htmARPCONTACTSupporto clientiARPHELPLINKhttp://www.adobe.com/it/sup" ascii
    $s16 = "t Explorer 7.0 o versione successiva. Per aggiornare Internet Explorer, visitare www.microsoft.com.LC_UNSUPPORTED_OSLC_UNSUPPORT" ascii
    $s17 = "ERROR_DEFRAG_ADTEMPLATEProcesso completato al [1]%ERROR_DEFRAG_MSGOttimizzazione delle prestazioni in corso...ERROR_MIN_OVER_BIG" ascii
    $s18 = " necessario aver installato Microsoft(R) .NET Framework.Impossibile eseguire il file script SQL [2]. Connessione non aperta: [3]" ascii
    $s19 = " stata rilevata la presenza di un altro visualizzatore PDF. Impostare Adobe Reader come visualizzatore PDF predefinito?UpdateMod" ascii
    $s20 = " terminata. Consultare i requisiti minimi di sistema, disponibili all'indirizzo http://www.adobe.com/go/reader_system_reqs_it.Un" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}