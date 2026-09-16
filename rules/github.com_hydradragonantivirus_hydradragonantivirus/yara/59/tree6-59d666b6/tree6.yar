rule tree6 {
  strings:
    $s0    = "fastIndexForKnownKey" fullword
    $s1    = "ZTIN2el4base9threading10ThreadSafeE" fullword
    $s2    = "handleEventsForBackgroundURLSession" fullword
    $s3    = "N5boost9exceptionE" fullword
    $s4    = "NSOpenStepRootDirectory" fullword
    $s5    = "relativeToWindow" fullword
    $s6    = "createTitlebarView" fullword
    $s7    = "previousblockhash" fullword
    $s8    = "isAppStoreDistribution" fullword
    $s9    = "EqualizationPhase1" fullword
    $s10   = "UHAWAVAUATSPILuI" fullword
    $s11   = "threadSafeMainBundle" fullword
    $s12   = "ZBNetworkReachability" fullword
    $s13   = "errcallEPPFvPK5DbEnvPKcS4" fullword
    $s14   = "kZBZeoAccountLoggedInNotification" fullword
    $s15   = "KGCustomMainWindowView" fullword
    $s16   = "IORegistryEntryCreateCFProperty" fullword
    $s17   = "Z83Z8CZ8SZ8cZ8sZ8" fullword
    $s18   = "UHAWAVAUATSHhDMLpHMHUHuE" fullword
    $s20   = "UHAWAVAUATSH8LMHMHUHuHH" fullword
    $s21   = "20160507105842Z0" fullword
    $s22   = "launchJavaApplication" fullword
    $s23   = "welcomeScreenIdentifier" fullword
    $s24   = "20191105000000Z0" fullword
    $s25   = "dictionaryWithJSONString" fullword
    $s26   = "showNotification" fullword
    $s27   = "ZL19transcribeProtocolsP10objc" fullword
    $s28   = "dictionaryWithContentsOfFile" fullword
    $s29   = "clickModifierFlags" fullword
    $s30   = "isJavaInstalledInternal" fullword
    $s31   = "UserNotifications" fullword
    $s32   = "UHAWAVAUATSHHHuE" fullword
    $s33   = "HuHUHEHHMHMHMHMHUHuHHuHHUH" fullword
    $s34   = "initWithSuiteName" fullword
    $s35   = "terminationStatus" fullword
    $s36   = "CFBundleIdentifier" fullword
    $s37   = "retainAutoreleasedReturnValue" fullword
    $s38   = "DEDEDEDEDEDEDEDE9E" fullword
    $s39   = "localizedStringForKey" fullword
    $s40   = "SystemConfiguration" fullword
    $s41   = "applicationWillUnhide" fullword
    $s42   = "URLRequestExtension" fullword
    $s43   = "efCkKaADK3CAKRCNC" fullword
    $s44   = "NSDistributedNotificationCenter" fullword
    $s45   = "AssemblyProductAttribute" fullword
    $s46   = "20191001103003Z0" fullword
    $s47   = "ServiceManagement" fullword
    $s48   = "EHMHMHMHMHMHMHMHMHMHMH" fullword
    $s49   = "210412223435Z0V1" fullword
    $s50   = "HMHMHMHMHMHMHMHML" fullword
    $s51   = "270201221215Z0y1" fullword
    $s52   = "NSAddressOfSymbol" fullword
    $s53   = "UHAWAVAUATSPIHIH" fullword
    $s54   = "logKextUserClient" fullword
    $s55   = "DefaultRuneLocale" fullword
    $s56   = "spDkrKTDKFCLC8CXD" fullword
    $s57   = "withIntermediateDirectories" fullword
    $s58   = "registerForMessageName" fullword
    $s59   = "iPhoneSimulator10" fullword
    $s60   = "libswiftCoreGraphics" fullword
    $s61   = "NSAutoreleasePool" fullword
    $s62   = "componentsSeparatedByString" fullword
    $s63   = "350209214036Z0b1" fullword
    $s64   = "AECreateAppleEvent" fullword
    $s65   = "stringWithFormat" fullword
    $s66   = "ellipticcurvelist" fullword
    $s67   = "NSPropertyListSerialization" fullword
    $s68   = "getInitializedObjCClass" fullword
    $s69   = "HMHMHMHMHMHMHMHMHMH" fullword
    $s70   = "kCFAllocatorDefault" fullword
    $s71   = "ImageCaptureCore" fullword
    $s72   = "traitsIcEEE9showmanycEv" fullword
    $s73   = "enumerationMutation" fullword
    $s74   = "NSConcreteGlobalBlock" fullword
    $s75   = "CFConstantStringClassReference" fullword
    $s76   = "DisableThreadLibraryCalls" fullword
    $s77   = "HMHMHMHMHMHMHMHMH" fullword
    $s78   = "ApplicationServices" fullword
    $s79   = "ZN9QListData7disposeEPNS" fullword
    $s81   = "ZNK12QMapNodeBase8nextNodeEv" fullword
    $s82   = "ddddddddddddddddddddddddddddddddsd" fullword
    $s83   = "ZN7QObject10childEventEP11QChildEvent" fullword
    $s84   = "0123456789abcdef" fullword
    $s85   = "JSObjectSetProperty" fullword
    $s86   = "contentsOfDirectoryAtPath" fullword
    $s87   = "HEHEHEHEHEHEHEHE" fullword
    $s88   = "copyElephantBrain" fullword
    $s89   = "UHAWAVAUATSH8IHH" fullword
    $s91   = "retainAutorelease" fullword
    $s92   = "UHAWAVAUATSH8HIH" fullword
    $s93   = "abcdefghijklmnopqrstuvwxyz" fullword
    $s94   = "9allocatorIcEEE6insertEmPKcm" fullword
    $s96   = "debugDescription" fullword
    $s97   = "IOIteratorIsValid" fullword
    $s98   = "OSAtomicDecrement32" fullword
    $s99   = "CFStringMakeConstantString" fullword
    $s100  = "NSNotificationCenter" fullword
    $s102  = "PrivateFrameworks" fullword
    $s103  = "fileExistsAtPath" fullword
    $s104  = "9allocatorIcEEEC1ERKS5" fullword
    $s107  = "FromStringAndSize" fullword
    $s108  = "9allocatorIcEEEE" fullword
    $s109  = "x2fvpr854319l6k9d06xlwt0rqm9vf" fullword
    $s110  = "UHAWAVAUATSH8IIH" fullword
    $s111  = "UIViewController" fullword
    $s112  = "numberWithDouble" fullword
    $s113  = "retainAutoreleaseReturnValue" fullword
    $s114  = "intrinsicContentSize" fullword
    $s115  = "libswiftDispatch" fullword
    $s116  = "lswiftObjectiveC" fullword
    $s117  = "NSStringFromClass" fullword
    $s118  = "respondsToSelector" fullword
    $s119  = "arrayWithObjects" fullword
    $s126  = "replaceCharactersInRange" fullword
    $s150  = "CFURLCopyFileSystemPath" fullword
    $s151  = "HEHEHEHEHEHEHEHEHEHEHE" fullword
    $s152  = "UHAWAVAUATSPIIID" fullword
    $s153  = "CFStringCreateWithCString" fullword
    $s157  = "HEHEHEHEHEHEHEHEHEHEHEHEI" fullword
    $s159  = "UHAWAVAUATSPIIHt" fullword
    $s160  = "category23default" fullword
    $s164  = "CFStringGetCString" fullword
    $s173  = "ZTSN5boost9exceptionE" fullword
    $s175  = "ZN9QListData11shared" fullword
    $s225  = "sharedApplication" fullword
    $s249  = "conformsToProtocol" fullword
    $s252  = "ZN16QLoggingCategoryD1Ev" fullword
    $s299  = "CFBundleGetVersionNumber" fullword
    $s304  = "arrayWithCapacity" fullword
    $s307  = "CFURLGetFileSystemRepresentation" fullword
    $s318  = "countByEnumeratingWithState" fullword
    $s322  = "substringToIndex" fullword
    $s323  = "e4zPO0A75QibEoIM1dS3ccGV3ag" fullword
    $s326  = "dataWithContentsOfFile" fullword
    $s328  = "certificateauthority" fullword
    $s331  = "completionHandler" fullword
    $s332  = "140305162647Z0A1" fullword
    $s336  = "140129192647Z0A1" fullword
    $s338  = "certificateauthority0" fullword
    $s339  = "140213191008Z0A1" fullword
    $s340  = "180123004003Z0A1" fullword
    $s354  = "CFDictionaryCreateMutable" fullword
    $s356  = "autoreleasePoolPop" fullword
    $s357  = "CFStreamCreatePairWithSocket" fullword
    $s361  = "200219223002Z0B1" fullword
    $s363  = "traitsIcEEE3putEc" fullword
    $s364  = "AuthorizationFree" fullword
    $s367  = "stringByAppendingPathComponent" fullword
    $s369  = "UHAWAVAUATSH8IIHH" fullword
    $s371  = "UHAWAVAUATSPAAII" fullword
    $s400  = "CFArrayGetValueAtIndex" fullword
    $s430  = "IntermediateBuildFilesPath" fullword
    $s433  = "getExistentialTypeMetadata" fullword
    $s434  = "191127221001Z0A1" fullword
    $s436  = "getTupleTypeMetadata2" fullword
    $s437  = "libswiftCoreFoundation" fullword
    $s441  = "MobileCoreServices" fullword
    $s442  = "NSLayoutConstraint" fullword
    $s480  = "NSOperationQueue" fullword
    $s485  = "applicationDidResignActive" fullword
    $s489  = "imageWithCGImage" fullword
    $s504  = "characterIsMember" fullword
    $s510  = "initWithCapacity" fullword
    $s528  = "didRegisterForRemoteNotificationsWithDeviceToken" fullword
    $s540  = "NSAssertionHandler" fullword
    $s552  = "NetworkExtension" fullword
    $s585  = "arrayWithJSONStringIgnoringNulls" fullword
    $s593  = "NSRunningApplication" fullword
    $s595  = "executeWithPrivileges" fullword
    $s596  = "facebookAccessToken" fullword
    $s597  = "leftRightGridient" fullword
    $s598  = "ZBInvocationOperation" fullword
    $s600  = "uriuwfgjZasjXjjgZm" fullword
    $s601  = "scanUnicodeCharacter" fullword
    $s602  = "ZBLocalizedString" fullword
    $s603  = "ZNK2cv3Mat5MStepixEi" fullword
    $s604  = "JKDictionaryClass" fullword
    $s605  = "applicationWillHide" fullword
    $s606  = "GenerateConnectionID" fullword
    $s608  = "Dfllononqpqpsrr2" fullword
    $s613  = "CGContextFillRect" fullword
    $s614  = "k7kBkQkpkkkkkkkkkkflmllllll" fullword
    $s619  = "200521020415Z0P1" fullword
    $s621  = "assertionFailure" fullword
    $s625  = "SecTrustSetNetworkFetchAllowed" fullword
    $s627  = "getRequiredClass" fullword
    $s632  = "getGenericMetadata1" fullword
    $s634  = "CFBundleShortVersionString" fullword
    $s654  = "ecpointformatlist" fullword
    $s658  = "alSourceQueueBuffers" fullword
    $s674  = "columnIndexForName" fullword
    $s705  = "objectForKeyedSubscript" fullword
    $s706  = "getImplementation" fullword
    $s707  = "NSMutableURLRequest" fullword
    $s708  = "scheduledTimerWithTimeInterval" fullword
    $s709  = "SCNetworkReachabilityUnscheduleFromRunLoop" fullword
    $s715  = "bundleIdentifier" fullword
    $s723  = "expectedContentLength" fullword
    $s724  = "certificationauthority" fullword
    $s728  = "glFramebufferTextureLayer" fullword
    $s798  = "fUHAWAVSPIHIIv0Ht" fullword
    $s803  = "cCFAttributedStringMBS" fullword
    $s804  = "NSMutableOrderedSet" fullword
    $s806  = "fHSUATAUAVIHHIHIHD" fullword
    $s815  = "301231000000Z0s1" fullword
    $s816  = "CFBundleInfoDictionaryVersion" fullword
    $s826  = "mediumspringgreen" fullword
    $s829  = "191128154500Z0A1" fullword
    $s832  = "ddddduhhhhhhhhhh" fullword
    $s839  = "StringCharCodeAt" fullword
    $s843  = "UHAWAVAUATSHhMMIH" fullword
    $s846  = "CFBundleCopyBundleURL" fullword
    $s848  = "encodeURIComponent" fullword
    $s851  = "initWithContentsOfURL" fullword
    $s979  = "traitsIcEEE5tellgEv" fullword
    $s980  = "15mutex6unlockEv" fullword
    $s992  = "dataUsingEncoding" fullword
    $s994  = "resignFirstResponder" fullword
    $s995  = "fileHandleForReading" fullword
    $s996  = "numberWithUnsignedLong" fullword
    $s999  = "CGContextStrokePath" fullword
    $s1004 = "systemFontOfSize" fullword
    $s1008 = "IOServiceTerminate" fullword
    $s1024 = "CFRunLoopGetMain" fullword
    $s1040 = "CFBundleCopyResourceURL" fullword
    $s1042 = "CGContextRelease" fullword
    $s1051 = "IOServiceGetMatchingServices" fullword
    $s1052 = "numberWithUnsignedInteger" fullword
    $s1061 = "stringWithUTF8String" fullword
    $s1062 = "ZBSystemInformation" fullword
    $s1069 = "setStandardOutput" fullword
    $s1075 = "createFileAtPath" fullword
    $s1078 = "indexOfTabViewItem" fullword
    $s1089 = "initWithFireDate" fullword
    $s1106 = "getInstanceMethod" fullword
    $s1108 = "defaultConfiguration" fullword
    $s1110 = "setAttributedTitle" fullword
    $s1115 = "CFNumberGetValue" fullword
    $s1116 = "uploadProgressDelegate" fullword
    $s1136 = "unzGoToFilePos64" fullword
    $s1137 = "ZN9QListData6appendERKS" fullword
    $s1153 = "ZN5xmrig6OclLib18getProgramBuildLogEP11" fullword
    $s1158 = "autoreleaseReturnValue" fullword
    $s1159 = "LSGetCurrentApplicationASN" fullword
    $s1161 = "getblocktemplate" fullword
    $s1168 = "UHAWAVAUATSPIHIIH" fullword
    $s1169 = "caseInsensitiveCompare" fullword
    $s1170 = "UHAWAVAUATSH8MIIL" fullword
    $s1200 = "G16ComparisonResultOtF" fullword
    $s1202 = "dataTaskWithRequest" fullword
    $s1219 = "kCFCoreFoundationVersionNumber" fullword
    $s1222 = "UHAWAVAUATSH8IHuIH" fullword
    $s1239 = "includingPropertiesForKeys" fullword
    $s1240 = "copyClassNamesForImage" fullword
    $s1242 = "setCanChooseDirectories" fullword
    $s1244 = "NSFilenamesPboardType" fullword
    $s1252 = "runningApplicationWithProcessIdentifier" fullword
    $s1259 = "componentsSeparatedByNewLine" fullword
    $s1264 = "Z83Z8CZ8SZ8cZ8sZ8z" fullword
    $s1272 = "stringWithCapacity" fullword
    $s1273 = "runningApplications" fullword
    $s1293 = "CGPathCreateMutable" fullword
    $s1296 = "createDirectoryAtURL" fullword
    $s1300 = "componentsSeparatedByCharactersInSet" fullword
    $s1315 = "timeIntervalSinceDate" fullword
    $s1320 = "IMBUserNotificationInstance" fullword
    $s1345 = "operatingSystemVersionString" fullword
    $s1353 = "selectorPFP11objc" fullword
    $s1367 = "replaceObjectAtIndex" fullword
    $s1368 = "navigationBarNodeSortingOrder" fullword
    $s1369 = "callToActionTitleForWelcomeViewController" fullword
    $s1378 = "allocatorI11FILE" fullword
    $s1383 = "FindPrevUserEntry" fullword
    $s1384 = "N5boost6detail11thread" fullword
    $s1397 = "ZNK5boost13match" fullword
    $s1402 = "ZTI15ISLogWriterBase" fullword
    $s1407 = "crossCertificatePair" fullword
    $s1413 = "ZTVN5boost4asio5error6detail12ssl" fullword
    $s1414 = "113EmptyIteratorE" fullword
    $s1427 = "34CachingTransactionSignatureChecker" fullword
    $s1429 = "ZN10CryptoNote16ConnectExceptionD1Ev" fullword
    $s1441 = "ZN5tools6base586encodeERKNSt3" fullword
    $s1447 = "NSAppleEventManager" fullword
    $s1449 = "2numBlocksChanged" fullword
    $s1457 = "didEndDisplayingHeaderView" fullword
    $s1458 = "s8Dispatch0A4TimeVMa" fullword
    $s1459 = "UpdateDialogRocket" fullword
    $s1460 = "willChangeStatusBarOrientation" fullword
    $s1462 = "NSJSONSerialization" fullword
    $s1464 = "TZFE10FoundationSS36" fullword
    $s1474 = "CSo12NSDictionary" fullword
    $s1480 = "bridgeToObjectiveCSo5NSURLCyF" fullword
    $s1483 = "KUNCGetNotificationID" fullword
    $s1486 = "UIAlertViewDelegate" fullword
    $s1497 = "connectionDidFinishLoading" fullword
    $s1498 = "UIGestureRecognizer" fullword
    $s1504 = "enumerateObjectsUsingBlock" fullword
    $s1514 = "kSecMatchLimitAll" fullword
    $s1518 = "WDYBRARARARARARARARARARARARARARARARARARARCRC" fullword
    $s1522 = "addEntriesFromDictionaryP11objc" fullword
    $s1523 = "forKeyedSubscriptP19NSMutableDictionaryP13objc" fullword
    $s1526 = "N14LoggingHelpers13WebLogMessageE" fullword
    $s1542 = "applyMacKeeperFlatDesign" fullword
    $s1549 = "setIsAccessibilityElement" fullword
    $s1550 = "loadWeakRetained" fullword
    $s1552 = "applicationDidUnhide" fullword
    $s1554 = "UHAWAVATSIII1Mt2Mt" fullword
    $s1569 = "applicationShouldOpenUntitledFile" fullword
    $s1576 = "kMDItemWhereFroms" fullword
    $s1589 = "continueUserActivity" fullword
    $s1591 = "backingScaleFactor" fullword
    $s1602 = "RGp0SARARARARARA" fullword
    $s1612 = "ARCLiteIndexedSubscripting" fullword
    $s1625 = "ZL16scanMangledFieldRPKcS0" fullword
    $s1631 = "JcBX2ZiyBahx4RJr4gGw3WIOY" fullword
    $s1643 = "didDismissWithButtonIndex" fullword
    $s1646 = "cancelAllOperations" fullword
    $s1647 = "otherButtonTitles" fullword
    $s1655 = "unretainedObject" fullword
    $s1659 = "ateAdBlockerSecondContentBlockerBundleIdentifier" fullword
    $s1673 = "willDismissWithButtonIndex" fullword
    $s1682 = "cancelButtonTitle" fullword
    $s1685 = "NSDistantObjectRequest" fullword
    $s1693 = "ASASASASASASASASASASB" fullword
    $s1717 = "replacementString" fullword
    $s1724 = "InitializeDistributedNotification" fullword
    $s1725 = "ATEContentBlockersRulesWereSet" fullword
    $s1728 = "SecTransformExecute" fullword
    $s1734 = "UHAWAVAUATSHHIH5M" fullword
    $s1744 = "absolutePathForRelativeTaskPath" fullword
    $s1767 = "ZL22copySwiftV1MangledNamePKcb" fullword
    $s1770 = "stringWithString" fullword
    $s1796 = "ContiguousaB0Vy7ElementQzGz" fullword
    $s1800 = "setSuccessSendingHandler" fullword
    $s1808 = "descriptionWithLocale" fullword
    $s1823 = "IOPlatformExpertDevice" fullword
    $s1825 = "allocBatchP11objc" fullword
    $s1839 = "LSCopyDefaultApplicationURLForURL" fullword
    $s1844 = "warnDelegateAboutMethods" fullword
    $s1850 = "outlineViewColumnDidResize" fullword
    $s1855 = "authenticationPolicy" fullword
    $s1859 = "localizedCaseInsensitiveCompare" fullword
    $s1864 = "ponponqqtsrtsruuxwvwvyy" fullword
    $s1875 = "didFinishDownloadingToURL" fullword
    $s1877 = "NSURLSessionDataTask" fullword
    $s1882 = "kSecAttrProtocolAFP" fullword
    $s1885 = "responseSerializer" fullword
    $s1887 = "kSecAttrAccessGroup" fullword
    $s1908 = "EXUa2Kc9Qd9ysfHNqqIFg" fullword

  condition:
    ((#s0 <= 0.5)
      and ((#s1 <= 1.0)
        and ((#s2 <= 0.5)
          and ((#s3 <= 0.5)
            and ((#s4 <= 2.5)
              and ((#s5 <= 0.5)
                and ((#s6 <= 2.0)
                  and ((#s7 <= 0.5)
                    and ((#s8 <= 0.5)
                      and ((#s9 <= 0.5)
                        and ((#s10 <= 0.5)
                          and ((#s11 <= 0.5)
                            and ((#s12 <= 0.5)
                              and ((#s13 <= 0.5)
                                and ((#s14 <= 1.0)
                                  and ((#s15 <= 0.5)
                                    and ((#s16 <= 1.5)
                                      and ((#s17 <= 0.5)
                                        and ((#s18 <= 0.5)
                                          and ((filesize <= 69604.0)
                                            and ((#s20 <= 0.5)
                                              and ((#s21 <= 0.5)
                                                and ((#s22 <= 1.5)
                                                  and ((#s23 <= 0.5)
                                                    and ((#s24 <= 0.5)
                                                      and ((#s25 <= 1.0)
                                                        and ((#s26 <= 0.5)
                                                          and ((#s27 <= 1.0)
                                                            and ((#s28 <= 1.5)
                                                              and ((#s29 <= 0.5)
                                                                and ((#s30 <= 1.5)
                                                                  and ((#s31 <= 1.5)
                                                                    and ((#s32 <= 0.5)
                                                                      and ((#s33 <= 0.5)
                                                                        and ((#s34 <= 0.5)
                                                                          and ((#s35 <= 0.5)
                                                                            and ((#s36 <= 0.5)
                                                                              and ((#s37 <= 0.5)
                                                                                and ((#s38 <= 0.5)
                                                                                  and ((#s39 <= 0.5)
                                                                                    and ((#s40 <= 0.5)
                                                                                      and ((#s41 <= 0.5)
                                                                                        and ((#s42 <= 4.5)
                                                                                          and ((#s43 <= 0.5)
                                                                                            and ((#s44 <= 1.0)
                                                                                              and ((#s45 <= 0.5)
                                                                                                and ((#s46 <= 0.5)
                                                                                                  and ((#s47 <= 2.5)
                                                                                                    and ((#s48 <= 0.5)
                                                                                                      and ((#s49 <= 0.5)
                                                                                                        and ((#s50 <= 0.5)
                                                                                                          and ((#s51 <= 0.5)
                                                                                                            and ((#s52 <= 0.5)
                                                                                                              and ((#s53 <= 0.5)
                                                                                                                and ((#s54 <= 1.0)
                                                                                                                  and ((#s55 <= 0.5)
                                                                                                                    and ((#s56 <= 0.5)
                                                                                                                      and ((#s57 <= 0.5)
                                                                                                                        and ((#s58 <= 0.5)
                                                                                                                          and ((#s59 <= 0.5)
                                                                                                                            and ((#s60 <= 0.5)
                                                                                                                              and ((#s61 <= 0.5)
                                                                                                                                and ((#s62 <= 0.5)
                                                                                                                                  and ((#s63 <= 0.5)
                                                                                                                                    and ((#s64 <= 0.5)
                                                                                                                                      and ((#s65 <= 0.5)
                                                                                                                                        and ((#s66 <= 1.0)
                                                                                                                                          and ((#s67 <= 1.0)
                                                                                                                                            and ((#s68 <= 0.5)
                                                                                                                                              and ((#s69 <= 0.5)
                                                                                                                                                and ((#s70 <= 0.5)
                                                                                                                                                  and ((#s71 <= 1.0)
                                                                                                                                                    and ((#s72 <= 0.5)
                                                                                                                                                      and ((#s73 <= 1.5)
                                                                                                                                                        and ((#s74 <= 0.5)
                                                                                                                                                          and ((#s75 <= 0.5)
                                                                                                                                                            and ((#s76 <= 1.0)
                                                                                                                                                              and ((#s77 <= 0.5)
                                                                                                                                                                and ((#s78 <= 0.5)
                                                                                                                                                                  and ((#s79 <= 0.5)
                                                                                                                                                                    and ((#s73 <= 0.5)
                                                                                                                                                                      and ((#s81 <= 1.0)
                                                                                                                                                                        and ((#s82 <= 0.5)
                                                                                                                                                                          and ((#s83 <= 0.5)
                                                                                                                                                                            and ((#s84 <= 0.5)
                                                                                                                                                                              and ((#s85 <= 1.0)
                                                                                                                                                                                and ((#s86 <= 0.5)
                                                                                                                                                                                  and ((#s87 <= 0.5)
                                                                                                                                                                                    and ((#s88 <= 1.5)
                                                                                                                                                                                      and ((#s89 <= 0.5)
                                                                                                                                                                                        and ((filesize <= 49632.0)
                                                                                                                                                                                          and ((#s91 <= 0.5)
                                                                                                                                                                                            and ((#s92 <= 0.5)
                                                                                                                                                                                              and ((#s93 <= 0.5)
                                                                                                                                                                                                and ((#s94 <= 0.5)
                                                                                                                                                                                                  and ((#s47 <= 1.0)
                                                                                                                                                                                                    and ((#s96 <= 0.5)
                                                                                                                                                                                                      and ((#s97 <= 1.0)
                                                                                                                                                                                                        and ((#s98 <= 0.5)
                                                                                                                                                                                                          and ((#s99 <= 0.5)
                                                                                                                                                                                                            and ((#s100 <= 1.0)
                                                                                                                                                                                                              and ((filesize <= 20788.0)
                                                                                                                                                                                                                and ((#s102 <= 0.5)
                                                                                                                                                                                                                  and ((#s103 <= 0.5)
                                                                                                                                                                                                                    and ((#s104 <= 0.5)
                                                                                                                                                                                                                      and ((filesize > 5164.0)
                                                                                                                                                                                                                        and ((#s107 <= 0.5)
                                                                                                                                                                                                                          and ((#s108 <= 2.0)
                                                                                                                                                                                                                            and ((#s109 <= 1.0)
                                                                                                                                                                                                                              and ((#s110 <= 0.5)
                                                                                                                                                                                                                                and ((#s111 <= 1.5)
                                                                                                                                                                                                                                  and ((#s112 <= 0.5)
                                                                                                                                                                                                                                    and ((#s113 <= 0.5)
                                                                                                                                                                                                                                      and ((#s114 <= 2.0)
                                                                                                                                                                                                                                        and ((#s115 <= 0.5)
                                                                                                                                                                                                                                          and ((#s116 <= 0.5)
                                                                                                                                                                                                                                            and ((#s117 <= 0.5)
                                                                                                                                                                                                                                              and ((#s118 <= 0.5)
                                                                                                                                                                                                                                                and ((#s119 <= 0.5)
                                                                                                                                                                                                                                                  and ((filesize <= 5206.5)
                                                                                                                                                                                                                                                    or (filesize > 5206.5)
                                                                                                                                                                                                                                                    and ((filesize > 12530.0)
                                                                                                                                                                                                                                                      and ((filesize <= 12570.0)
                                                                                                                                                                                                                                                        or (filesize > 12570.0)
                                                                                                                                                                                                                                                        and ((#s126 <= 0.5)
                                                                                                                                                                                                                                                          and ((filesize > 16428.0)
                                                                                                                                                                                                                                                            and ((filesize <= 16490.0)
                                                                                                                                                                                                                                                            ))))))))))))))))))))))) or (filesize > 20788.0)
                                                                                                                                                                                                                and ((#s115 <= 0.5)
                                                                                                                                                                                                                  and ((#s150 <= 0.5)
                                                                                                                                                                                                                    and ((#s151 <= 0.5)
                                                                                                                                                                                                                      and ((#s152 <= 0.5)
                                                                                                                                                                                                                        and ((#s153 <= 0.5)
                                                                                                                                                                                                                          and ((#s107 <= 0.5)
                                                                                                                                                                                                                            and ((#s102 <= 0.5)
                                                                                                                                                                                                                              and ((#s111 <= 0.5)
                                                                                                                                                                                                                                and ((#s157 <= 0.5)
                                                                                                                                                                                                                                  and ((#s104 <= 1.0)
                                                                                                                                                                                                                                    and ((#s159 <= 0.5)
                                                                                                                                                                                                                                      and ((#s160 <= 3.0)
                                                                                                                                                                                                                                        and ((#s109 <= 1.5)
                                                                                                                                                                                                                                          and ((filesize <= 20802.0)
                                                                                                                                                                                                                                            or (filesize > 20802.0)
                                                                                                                                                                                                                                            and ((#s164 <= 0.5)
                                                                                                                                                                                                                                              and ((filesize <= 21332.0)
                                                                                                                                                                                                                                                and ((filesize <= 21250.0)
                                                                                                                                                                                                                                                  and ((filesize > 21020.0)
                                                                                                                                                                                                                                                    and ((filesize <= 21130.0)
                                                                                                                                                                                                                                                    )) or (filesize > 21250.0)
                                                                                                                                                                                                                                                ) or (filesize > 21332.0)
                                                                                                                                                                                                                                                and ((#s173 <= 0.5)
                                                                                                                                                                                                                                                  and ((#s108 <= 0.5)
                                                                                                                                                                                                                                                    and ((#s175 <= 0.5)
                                                                                                                                                                                                                                                      and ((filesize <= 26130.0)
                                                                                                                                                                                                                                                        and ((#s116 <= 0.5)
                                                                                                                                                                                                                                                          and ((filesize <= 26048.0)
                                                                                                                                                                                                                                                            and ((filesize > 25096.0)
                                                                                                                                                                                                                                                              and ((filesize <= 25256.0)
                                                                                                                                                                                                                                                              )) or (filesize > 26048.0)
                                                                                                                                                                                                                                                          )) or (filesize > 26130.0)
                                                                                                                                                                                                                                                        and ((filesize > 32970.0)
                                                                                                                                                                                                                                                          and ((filesize <= 33116.0)
                                                                                                                                                                                                                                                            or (filesize > 33116.0)
                                                                                                                                                                                                                                                            and ((filesize <= 38360.0)
                                                                                                                                                                                                                                                              and ((filesize > 38276.0)
                                                                                                                                                                                                                                                              ))))))))))))))) or (#s157 > 0.5)
                                                                                                                                                                                                                                )))))) or (#s151 > 0.5)
                                                                                                                                                                                                                    )))))))))))))) or (filesize > 49632.0)
                                                                                                                                                                                          and ((#s110 <= 0.5)
                                                                                                                                                                                            and ((#s107 <= 0.5)
                                                                                                                                                                                              and ((#s116 <= 0.5)
                                                                                                                                                                                                and ((#s225 <= 0.5)
                                                                                                                                                                                                  and ((#s109 <= 1.5)
                                                                                                                                                                                                    and ((filesize <= 50238.0)
                                                                                                                                                                                                      and ((filesize <= 50174.5)
                                                                                                                                                                                                        or (filesize > 50174.5)
                                                                                                                                                                                                        and ((filesize > 50178.5)
                                                                                                                                                                                                        )))))))))) or (#s88 > 1.5)
                                                                                                                                                                                    ) or (#s87 > 0.5)
                                                                                                                                                                                  ))) or (#s84 > 0.5)
                                                                                                                                                                              and ((#s109 <= 2.5)
                                                                                                                                                                                and ((filesize <= 37672.0)
                                                                                                                                                                                ))) or (#s83 > 0.5)
                                                                                                                                                                            and ((#s249 <= 0.5)
                                                                                                                                                                              and ((filesize > 40606.0)
                                                                                                                                                                                and ((#s252 <= 1.0)
                                                                                                                                                                                  and ((#s83 > 1.5)
                                                                                                                                                                                    and ((filesize <= 41546.0)
                                                                                                                                                                                    )))))) or (#s82 > 0.5)
                                                                                                                                                                        ))))) or (#s77 > 0.5)
                                                                                                                                                                and ((filesize <= 46744.5)
                                                                                                                                                                ))))) or (#s73 > 1.5)
                                                                                                                                                        and ((filesize <= 26000.0)
                                                                                                                                                        ))))) or (#s69 > 0.5)
                                                                                                                                              ))))))))))) or (#s58 > 0.5)
                                                                                                                        )) or (#s56 > 0.5)
                                                                                                                    )) or (#s54 > 1.0)
                                                                                                                )) or (#s52 > 0.5)
                                                                                                              and ((#s67 <= 2.0)
                                                                                                                and ((#s55 > 1.5)
                                                                                                                ))) or (#s51 > 0.5)
                                                                                                            and ((#s299 <= 0.5)
                                                                                                              and ((#s83 <= 0.5)
                                                                                                                and ((#s63 <= 1.5)
                                                                                                                  and ((#s70 <= 1.0)
                                                                                                                    and ((#s225 <= 0.5)
                                                                                                                      and ((#s304 <= 0.5)
                                                                                                                        and ((#s74 <= 1.0)
                                                                                                                          and ((#s153 <= 0.5)
                                                                                                                            and ((#s307 > 1.0)
                                                                                                                              and ((filesize <= 19912.0)
                                                                                                                              ))) or (#s74 > 1.0)
                                                                                                                          and ((#s86 <= 0.5)
                                                                                                                          )))) or (#s70 > 1.0)
                                                                                                                    and ((#s318 > 0.5)
                                                                                                                    )) or (#s63 > 1.5)
                                                                                                                  and ((#s74 <= 1.0)
                                                                                                                    and ((#s322 <= 0.5)
                                                                                                                      and ((#s323 <= 0.5)
                                                                                                                        and ((#s110 <= 1.0)
                                                                                                                          and ((#s225 <= 0.5)
                                                                                                                            and ((#s326 <= 0.5)
                                                                                                                              and ((#s107 <= 1.0)
                                                                                                                                and ((#s328 <= 0.5)
                                                                                                                                  and ((filesize <= 23992.0)
                                                                                                                                    and ((filesize <= 23872.0)
                                                                                                                                      and ((#s331 <= 1.0)
                                                                                                                                        and ((#s332 <= 0.5)
                                                                                                                                          and ((#s61 <= 1.0)
                                                                                                                                            and ((#s75 <= 1.0)
                                                                                                                                              and ((#s47 <= 1.0)
                                                                                                                                                and ((#s336 <= 0.5)
                                                                                                                                                  and ((#s102 <= 0.5)
                                                                                                                                                    and ((#s338 <= 0.5)
                                                                                                                                                      and ((#s339 <= 0.5)
                                                                                                                                                        and ((#s340 > 0.5)
                                                                                                                                                        ) or (#s339 > 0.5)
                                                                                                                                                      ))) or (#s336 > 0.5)
                                                                                                                                                )))) or (#s332 > 0.5)
                                                                                                                                        )) or (filesize > 23872.0)
                                                                                                                                    ) or (filesize > 23992.0)
                                                                                                                                    and ((#s62 <= 0.5)
                                                                                                                                      and ((#s354 <= 0.5)
                                                                                                                                        and ((#s102 <= 1.0)
                                                                                                                                          and ((#s356 <= 1.0)
                                                                                                                                            and ((#s357 <= 1.0)
                                                                                                                                              and ((#s153 <= 0.5)
                                                                                                                                                and ((#s70 <= 1.0)
                                                                                                                                                  and ((#s307 <= 1.0)
                                                                                                                                                    and ((#s361 <= 0.5)
                                                                                                                                                      and ((#s100 <= 1.0)
                                                                                                                                                        and ((#s363 <= 1.0)
                                                                                                                                                          and ((#s364 <= 0.5)
                                                                                                                                                            and ((#s47 <= 1.0)
                                                                                                                                                              and ((#s119 <= 0.5)
                                                                                                                                                                and ((#s367 <= 0.5)
                                                                                                                                                                  and ((#s51 <= 1.5)
                                                                                                                                                                    and ((#s369 <= 0.5)
                                                                                                                                                                      and ((#s84 <= 0.5)
                                                                                                                                                                        and ((#s371 <= 0.5)
                                                                                                                                                                          and ((filesize > 36568.0)
                                                                                                                                                                            and ((#s53 <= 0.5)
                                                                                                                                                                              and ((#s338 <= 0.5)
                                                                                                                                                                                and ((filesize <= 36984.0)
                                                                                                                                                                                )))))))))))))))))))))))) or (#s328 > 0.5)
                                                                                                                                  and ((#s400 <= 1.0)
                                                                                                                                    and ((filesize > 68895.5)
                                                                                                                                    ))))))) or (#s323 > 0.5)
                                                                                                                      ))))) or (#s299 > 0.5)
                                                                                                              and ((filesize <= 20408.0)
                                                                                                              ))) or (#s50 > 0.5)
                                                                                                        )) or (#s48 > 0.5)
                                                                                                    ) or (#s47 > 2.5)
                                                                                                    and ((#s364 <= 1.0)
                                                                                                    )) or (#s46 > 0.5)
                                                                                                ) or (#s45 > 0.5)
                                                                                              )) or (#s43 > 0.5)
                                                                                          ) or (#s42 > 4.5)
                                                                                        ) or (#s41 > 0.5)
                                                                                        and ((#s318 <= 0.5)
                                                                                        )) or (#s40 > 0.5)
                                                                                      and ((#s430 <= 0.5)
                                                                                        and ((#s78 <= 1.0)
                                                                                          and ((#s74 <= 0.5)
                                                                                            and ((#s433 <= 0.5)
                                                                                              and ((#s434 <= 0.5)
                                                                                                and ((#s75 <= 0.5)
                                                                                                  and ((#s436 <= 0.5)
                                                                                                    and ((#s437 <= 0.5)
                                                                                                      and ((#s115 <= 0.5)
                                                                                                        and ((#s31 <= 0.5)
                                                                                                          and ((#s59 <= 1.0)
                                                                                                            and ((#s441 <= 1.0)
                                                                                                              and ((#s442 <= 1.5)
                                                                                                                and ((#s68 <= 0.5)
                                                                                                                  and ((#s102 <= 1.0)
                                                                                                                    and ((#s328 <= 0.5)
                                                                                                                      and ((#s400 <= 1.0)
                                                                                                                        and ((#s40 > 1.5)
                                                                                                                          and ((#s63 <= 0.5)
                                                                                                                            and ((filesize > 17932.0)
                                                                                                                              and ((filesize <= 19830.0)
                                                                                                                              )))))))))))))))))))))) or (#s39 > 0.5)
                                                                                    and ((#s57 > 0.5)
                                                                                      and ((#s304 > 0.5)
                                                                                      ))) or (#s38 > 0.5)
                                                                                ) or (#s37 > 0.5)
                                                                                and ((#s91 <= 0.5)
                                                                                  and ((#s480 <= 0.5)
                                                                                    and ((#s59 <= 0.5)
                                                                                      and ((#s119 <= 0.5)
                                                                                        and ((#s75 > 1.5)
                                                                                          and ((#s485 <= 0.5)
                                                                                            and ((#s39 > 0.5)
                                                                                              and ((#s318 <= 0.5)
                                                                                                and ((#s489 <= 0.5)
                                                                                                  and ((#s89 <= 0.5)
                                                                                                    and ((#s338 <= 0.5)
                                                                                                    )))))))))))) or (#s36 > 0.5)
                                                                              and ((#s78 > 1.0)
                                                                                and ((#s504 <= 0.5)
                                                                                  and ((#s40 > 1.0)
                                                                                  )))) or (#s35 > 0.5)
                                                                            and ((#s78 <= 1.0)
                                                                              and ((#s510 <= 0.5)
                                                                                and ((#s326 <= 0.5)
                                                                                  and ((#s100 <= 0.5)
                                                                                    and ((filesize <= 24524.0)
                                                                                      and ((#s356 <= 1.0)
                                                                                      )) or (#s100 > 0.5)
                                                                                    and ((#s118 > 0.5)
                                                                                    )))))) or (#s34 > 0.5)
                                                                          and ((#s118 <= 0.5)
                                                                            and ((#s51 > 0.5)
                                                                            ) or (#s118 > 0.5)
                                                                            and ((#s528 > 0.5)
                                                                            ))) or (#s33 > 0.5)
                                                                        and ((#s51 <= 0.5)
                                                                          and ((filesize <= 21498.0)
                                                                          ))) or (#s32 > 0.5)
                                                                    ) or (#s31 > 1.5)
                                                                    and ((#s71 <= 1.0)
                                                                      and ((#s102 <= 1.5)
                                                                        and ((#s39 <= 0.5)
                                                                          and ((#s540 <= 0.5)
                                                                            and ((#s59 <= 5.0)
                                                                              and ((#s47 <= 1.0)
                                                                                and ((#s73 <= 0.5)
                                                                                  and ((#s31 <= 3.0)
                                                                                    and ((#s60 <= 0.5)
                                                                                      and ((#s441 <= 1.0)
                                                                                        and ((filesize > 24712.0)
                                                                                        ) or (#s441 > 1.0)
                                                                                        and ((filesize <= 13512.0)
                                                                                          and ((filesize <= 12038.0)
                                                                                            and ((#s552 <= 0.5)
                                                                                              and ((filesize > 8760.0)
                                                                                              ))) or (filesize > 13512.0)
                                                                                          and ((filesize <= 28092.0)
                                                                                            and ((filesize <= 16584.0)
                                                                                              and ((filesize <= 15560.0)
                                                                                                and ((filesize <= 14536.0)
                                                                                                ) or (filesize > 15560.0)
                                                                                              ))))))))))))))) or (#s30 > 1.5)
                                                                ) or (#s29 > 0.5)
                                                              ) or (#s28 > 1.5)
                                                            ) or (#s27 > 1.0)
                                                          ) or (#s26 > 0.5)
                                                        ) or (#s25 > 1.0)
                                                        and ((#s585 > 0.5)
                                                        )) or (#s24 > 0.5)
                                                    ) or (#s23 > 0.5)
                                                  ) or (#s22 > 1.5)
                                                ) or (#s21 > 0.5)
                                              ) or (#s20 > 0.5)
                                            ) or (filesize > 69604.0)
                                            and ((#s593 <= 0.5)
                                              and ((#s84 <= 0.5)
                                                and ((#s595 <= 1.0)
                                                  and ((#s596 <= 1.0)
                                                    and ((#s597 <= 0.5)
                                                      and ((#s598 <= 0.5)
                                                        and ((#s175 <= 0.5)
                                                          and ((#s600 <= 0.5)
                                                            and ((#s601 <= 0.5)
                                                              and ((#s602 <= 0.5)
                                                                and ((#s603 <= 2.0)
                                                                  and ((#s604 <= 0.5)
                                                                    and ((#s605 <= 0.5)
                                                                      and ((#s606 <= 1.0)
                                                                        and ((#s68 <= 1.5)
                                                                          and ((#s608 <= 0.5)
                                                                            and ((#s75 <= 0.5)
                                                                              and ((#s72 <= 1.5)
                                                                                and ((#s55 <= 1.5)
                                                                                  and ((#s83 <= 0.5)
                                                                                    and ((#s613 <= 0.5)
                                                                                      and ((#s614 <= 0.5)
                                                                                        and ((filesize <= 458376.0)
                                                                                          and ((#s104 <= 0.5)
                                                                                            and ((#s109 <= 1.0)
                                                                                              and ((#s93 <= 1.5)
                                                                                                and ((#s619 <= 0.5)
                                                                                                  and ((#s31 <= 1.5)
                                                                                                    and ((#s621 <= 0.5)
                                                                                                      and ((#s442 <= 0.5)
                                                                                                        and ((#s89 <= 0.5)
                                                                                                          and ((#s52 <= 0.5)
                                                                                                            and ((#s625 <= 0.5)
                                                                                                              and ((#s338 <= 0.5)
                                                                                                                and ((#s627 <= 0.5)
                                                                                                                  and ((#s322 <= 0.5)
                                                                                                                    and ((#s76 <= 0.5)
                                                                                                                      and ((#s164 <= 0.5)
                                                                                                                        and ((#s152 <= 0.5)
                                                                                                                          and ((#s632 <= 0.5)
                                                                                                                            and ((#s51 <= 0.5)
                                                                                                                              and ((#s634 <= 0.5)
                                                                                                                                and ((#s100 <= 0.5)
                                                                                                                                  and ((#s115 <= 0.5)
                                                                                                                                    and ((#s119 <= 0.5)
                                                                                                                                      and ((#s93 <= 0.5)
                                                                                                                                        and ((#s369 <= 0.5)
                                                                                                                                          and ((filesize <= 173174.0)
                                                                                                                                            and ((#s328 <= 0.5)
                                                                                                                                              and ((#s441 <= 0.5)
                                                                                                                                                and ((#s107 <= 0.5)
                                                                                                                                                  and ((#s307 <= 0.5)
                                                                                                                                                    and ((#s59 <= 0.5)
                                                                                                                                                      and ((#s153 <= 1.0)
                                                                                                                                                        and ((#s37 <= 0.5)
                                                                                                                                                          and ((#s25 <= 0.5)
                                                                                                                                                            and ((#s73 <= 0.5)
                                                                                                                                                              and ((#s33 <= 0.5)
                                                                                                                                                                and ((#s78 <= 1.0)
                                                                                                                                                                  and ((#s63 <= 0.5)
                                                                                                                                                                    and ((#s108 <= 0.5)
                                                                                                                                                                      and ((#s654 <= 1.0)
                                                                                                                                                                        and ((filesize <= 79752.0)
                                                                                                                                                                          and ((#s110 <= 1.5)
                                                                                                                                                                            and ((#s55 <= 0.5)
                                                                                                                                                                              and ((#s658 <= 1.0)
                                                                                                                                                                                and ((#s40 <= 1.0)
                                                                                                                                                                                  and ((filesize <= 79704.0)
                                                                                                                                                                                    and ((filesize <= 71180.0)
                                                                                                                                                                                      and ((filesize > 71036.0)
                                                                                                                                                                                      )) or (filesize > 79704.0)
                                                                                                                                                                                  ))))) or (filesize > 79752.0)
                                                                                                                                                                          and ((#s94 <= 0.5)
                                                                                                                                                                            and ((#s53 <= 0.5)
                                                                                                                                                                              and ((#s102 <= 1.0)
                                                                                                                                                                                and ((#s674 <= 0.5)
                                                                                                                                                                                  and ((#s110 <= 0.5)
                                                                                                                                                                                    and ((filesize <= 99374.0)
                                                                                                                                                                                      and ((#s74 <= 0.5)
                                                                                                                                                                                        and ((filesize > 99224.0)
                                                                                                                                                                                        ))))))))))))))))))))))) or (filesize > 173174.0)
                                                                                                                                            and ((#s72 <= 0.5)
                                                                                                                                              and ((#s356 <= 1.0)
                                                                                                                                                and ((#s74 <= 1.5)
                                                                                                                                                  and ((#s705 <= 0.5)
                                                                                                                                                    and ((#s706 <= 0.5)
                                                                                                                                                      and ((#s707 <= 0.5)
                                                                                                                                                        and ((#s708 <= 0.5)
                                                                                                                                                          and ((#s709 <= 0.5)
                                                                                                                                                            and ((#s371 <= 0.5)
                                                                                                                                                              and ((#s480 <= 0.5)
                                                                                                                                                                and ((#s59 <= 1.0)
                                                                                                                                                                  and ((#s110 <= 0.5)
                                                                                                                                                                    and ((#s73 <= 0.5)
                                                                                                                                                                      and ((#s715 <= 0.5)
                                                                                                                                                                        and ((#s328 <= 1.0)
                                                                                                                                                                          and ((#s94 <= 0.5)
                                                                                                                                                                            and ((#s78 <= 0.5)
                                                                                                                                                                              and ((#s55 <= 0.5)
                                                                                                                                                                                and ((#s441 <= 1.0)
                                                                                                                                                                                  and ((#s33 <= 0.5)
                                                                                                                                                                                    and ((#s92 <= 0.5)
                                                                                                                                                                                      and ((#s723 <= 0.5)
                                                                                                                                                                                        and ((#s724 <= 0.5)
                                                                                                                                                                                          and ((#s63 <= 0.5)
                                                                                                                                                                                            and ((#s53 <= 0.5)
                                                                                                                                                                                              and ((#s108 <= 0.5)
                                                                                                                                                                                                and ((#s728 <= 0.5)
                                                                                                                                                                                                  and ((#s87 <= 0.5)
                                                                                                                                                                                                    and ((#s40 <= 1.0)
                                                                                                                                                                                                      and ((#s99 <= 0.5)
                                                                                                                                                                                                        and ((filesize <= 173876.0)
                                                                                                                                                                                                          or (filesize > 173876.0)
                                                                                                                                                                                                          and ((#s102 <= 1.0)
                                                                                                                                                                                                            and ((filesize > 409912.0)
                                                                                                                                                                                                              and ((#s107 <= 2.5)
                                                                                                                                                                                                                and ((filesize <= 415252.0)
                                                                                                                                                                                                                ))))))))))))))))))))) or (#s715 > 0.5)
                                                                                                                                                                      )))))))))))))))))))))))))))))))))) or (#s31 > 1.5)
                                                                                                    and ((filesize <= 89764.0)
                                                                                                      and ((filesize > 80452.0)
                                                                                                      )))) or (#s93 > 1.5)
                                                                                                and ((#s798 > 0.5)
                                                                                                )))) or (filesize > 458376.0)
                                                                                          and ((#s803 <= 0.5)
                                                                                            and ((#s804 <= 0.5)
                                                                                              and ((#s249 <= 0.5)
                                                                                                and ((#s806 <= 0.5)
                                                                                                  and ((#s31 <= 1.0)
                                                                                                    and ((#s72 <= 0.5)
                                                                                                      and ((#s53 <= 1.5)
                                                                                                        and ((#s73 <= 0.5)
                                                                                                          and ((#s53 <= 0.5)
                                                                                                            and ((#s356 <= 0.5)
                                                                                                              and ((#s74 <= 0.5)
                                                                                                                and ((#s153 <= 0.5)
                                                                                                                  and ((#s815 <= 0.5)
                                                                                                                    and ((#s816 <= 0.5)
                                                                                                                      and ((#s33 <= 0.5)
                                                                                                                        and ((#s159 <= 0.5)
                                                                                                                          and ((#s70 <= 0.5)
                                                                                                                            and ((#s707 <= 2.0)
                                                                                                                              and ((#s371 <= 0.5)
                                                                                                                                and ((#s93 <= 0.5)
                                                                                                                                  and ((#s363 <= 1.0)
                                                                                                                                    and ((#s55 <= 0.5)
                                                                                                                                      and ((#s78 <= 0.5)
                                                                                                                                        and ((#s826 <= 0.5)
                                                                                                                                          and ((#s68 <= 0.5)
                                                                                                                                            and ((#s102 <= 0.5)
                                                                                                                                              and ((#s829 <= 0.5)
                                                                                                                                                and ((#s369 <= 0.5)
                                                                                                                                                  and ((#s52 <= 0.5)
                                                                                                                                                    and ((#s832 <= 0.5)
                                                                                                                                                      and ((#s654 <= 91.0)
                                                                                                                                                        and ((#s111 <= 0.5)
                                                                                                                                                          and ((#s76 <= 1.5)
                                                                                                                                                            and ((#s92 <= 0.5)
                                                                                                                                                              and ((#s98 <= 1.5)
                                                                                                                                                                and ((#s89 <= 0.5)
                                                                                                                                                                  and ((#s839 <= 1.0)
                                                                                                                                                                    and ((#s328 <= 0.5)
                                                                                                                                                                      and ((#s441 <= 1.0)
                                                                                                                                                                        and ((#s728 <= 0.5)
                                                                                                                                                                          and ((#s843 <= 0.5)
                                                                                                                                                                            and ((filesize <= 459332.0)
                                                                                                                                                                              or (filesize > 459332.0)
                                                                                                                                                                              and ((#s846 <= 0.5)
                                                                                                                                                                                and ((#s40 <= 1.0)
                                                                                                                                                                                  and ((#s848 <= 0.5)
                                                                                                                                                                                    and ((#s107 <= 0.5)
                                                                                                                                                                                      and ((#s35 <= 0.5)
                                                                                                                                                                                        and ((#s851 <= 3.5)
                                                                                                                                                                                          and ((#s338 <= 0.5)
                                                                                                                                                                                            and ((#s110 <= 0.5)
                                                                                                                                                                                              and ((#s354 <= 0.5)
                                                                                                                                                                                                and ((#s63 <= 0.5)
                                                                                                                                                                                                  and ((#s94 <= 0.5)
                                                                                                                                                                                                    and ((#s109 <= 1.0)
                                                                                                                                                                                                      and ((#s108 <= 44.0)
                                                                                                                                                                                                        and ((filesize <= 624454.0)
                                                                                                                                                                                                          and ((filesize > 615352.0)
                                                                                                                                                                                                          ) or (filesize > 624454.0)
                                                                                                                                                                                                          and ((filesize > 1826418.5)
                                                                                                                                                                                                            and ((#s152 <= 0.5)
                                                                                                                                                                                                              and ((filesize <= 1933213.5)
                                                                                                                                                                                                              ))))))))))))))) or (#s40 > 1.0)
                                                                                                                                                                                  and ((filesize <= 624612.0)
                                                                                                                                                                                    and ((filesize > 538150.0)
                                                                                                                                                                                    ))))))) or (#s441 > 1.0)
                                                                                                                                                                        and ((filesize > 2068452.0)
                                                                                                                                                                          and ((filesize <= 5001522.0)
                                                                                                                                                                          ))))))))))) or (#s832 > 0.5)
                                                                                                                                                    )))))))))) or (#s93 > 0.5)
                                                                                                                                  and ((#s93 <= 2.5)
                                                                                                                                    and ((#s361 <= 0.5)
                                                                                                                                      and ((#s51 <= 0.5)
                                                                                                                                        and ((#s110 <= 0.5)
                                                                                                                                          and ((#s93 > 1.5)
                                                                                                                                            and ((#s40 <= 1.0)
                                                                                                                                              and ((filesize <= 523753.5)
                                                                                                                                              )))))))))))) or (#s33 > 0.5)
                                                                                                                      )))))) or (#s53 > 0.5)
                                                                                                            and ((#s63 <= 1.0)
                                                                                                              and ((#s47 <= 1.0)
                                                                                                                and ((#s371 <= 14.5)
                                                                                                                  and ((#s92 <= 0.5)
                                                                                                                    and ((filesize <= 30531952.0)
                                                                                                                      and ((#s110 <= 1.0)
                                                                                                                        and ((filesize > 2236289.0)
                                                                                                                          and ((filesize <= 15940403.0)
                                                                                                                          ))) or (filesize > 30531952.0)
                                                                                                                    ))))))))))))) or (#s803 > 0.5)
                                                                                          )) or (#s614 > 0.5)
                                                                                      )))) or (#s72 > 1.5)
                                                                                and ((#s153 <= 1.0)
                                                                                  and ((#s104 > 3.0)
                                                                                    and ((#s369 <= 0.5)
                                                                                      and ((#s160 <= 1.0)
                                                                                        and ((#s164 <= 1.0)
                                                                                          and ((#s63 <= 0.5)
                                                                                            and ((#s363 > 1.0)
                                                                                              and ((#s979 <= 1.0)
                                                                                                and ((#s980 > 1.0)
                                                                                                  and ((#s108 > 31.5)
                                                                                                  ))))) or (#s164 > 1.0)
                                                                                        )))))) or (#s75 > 0.5)
                                                                              and ((#s35 <= 1.5)
                                                                                and ((#s992 <= 0.5)
                                                                                  and ((#s153 <= 1.5)
                                                                                    and ((#s994 <= 9.0)
                                                                                      and ((#s995 <= 0.5)
                                                                                        and ((#s996 <= 0.5)
                                                                                          and ((#s49 <= 0.5)
                                                                                            and ((#s37 <= 0.5)
                                                                                              and ((#s999 <= 0.5)
                                                                                                and ((#s504 <= 0.5)
                                                                                                  and ((#s78 <= 0.5)
                                                                                                    and ((filesize <= 2963196.5)
                                                                                                      and ((filesize <= 120048.0)
                                                                                                        and ((#s1004 <= 0.5)
                                                                                                          and ((#s103 <= 0.5)
                                                                                                            and ((#s304 <= 0.5)
                                                                                                              and ((#s73 <= 0.5)
                                                                                                                and ((#s1008 <= 0.5)
                                                                                                                  and ((#s93 <= 1.5)
                                                                                                                    and ((#s104 <= 1.0)
                                                                                                                      and ((#s28 <= 1.0)
                                                                                                                        and ((#s75 > 3.0)
                                                                                                                        )))))))))) or (filesize > 2963196.5)
                                                                                                      and ((#s1024 <= 1.0)
                                                                                                        and ((#s434 <= 0.5)
                                                                                                          and ((#s851 <= 0.5)
                                                                                                            and ((#s72 <= 0.5)
                                                                                                              and ((#s846 > 0.5)
                                                                                                              )))))))) or (#s999 > 0.5)
                                                                                                and ((#s1024 <= 0.5)
                                                                                                  and ((#s61 > 1.5)
                                                                                                    and ((#s1040 > 0.5)
                                                                                                      and ((#s1042 <= 2.5)
                                                                                                        and ((#s164 > 0.5)
                                                                                                        ))))))))) or (#s995 > 0.5)
                                                                                        and ((#s1051 <= 0.5)
                                                                                          and ((#s1052 > 0.5)
                                                                                          ))) or (#s994 > 9.0)
                                                                                    )) or (#s992 > 0.5)
                                                                                  and ((#s74 <= 0.5)
                                                                                    and ((#s57 <= 0.5)
                                                                                      and ((#s78 <= 3.5)
                                                                                        and ((#s1061 <= 0.5)
                                                                                          and ((#s1062 > 0.5)
                                                                                          )) or (#s78 > 3.5)
                                                                                        and ((#s299 <= 0.5)
                                                                                          and ((filesize > 288042.0)
                                                                                            and ((#s1069 <= 1.0)
                                                                                            )))) or (#s57 > 0.5)
                                                                                      and ((#s78 > 1.0)
                                                                                        and ((#s1075 <= 0.5)
                                                                                          and ((#s100 <= 3.0)
                                                                                            and ((#s96 <= 0.5)
                                                                                              and ((#s1078 <= 0.5)
                                                                                                and ((#s540 > 1.0)
                                                                                                )) or (#s96 > 0.5)
                                                                                              and ((#s225 <= 0.5)
                                                                                                and ((#s318 > 0.5)
                                                                                                )))) or (#s1075 > 0.5)
                                                                                          and ((#s1089 > 0.5)
                                                                                          )))) or (#s74 > 0.5)
                                                                                    and ((#s104 > 3.0)
                                                                                      and ((#s433 > 0.5)
                                                                                      )))) or (#s35 > 1.5)
                                                                                and ((#s331 > 10.5)
                                                                                ))) or (#s608 > 0.5)
                                                                          )) or (#s606 > 1.0)
                                                                      ) or (#s605 > 0.5)
                                                                      and ((#s332 <= 0.5)
                                                                        and ((#s78 <= 1.0)
                                                                          and ((#s164 <= 0.5)
                                                                            and ((#s1106 <= 1.0)
                                                                              and ((#s61 <= 0.5)
                                                                                and ((#s1108 <= 2.5)
                                                                                  and ((#s356 <= 1.0)
                                                                                    and ((#s1110 <= 0.5)
                                                                                    ))) or (#s61 > 0.5)
                                                                                and ((#s1115 <= 1.0)
                                                                                  and ((#s1116 > 0.5)
                                                                                  )))))) or (#s332 > 0.5)
                                                                      )) or (#s604 > 0.5)
                                                                  ) or (#s603 > 2.0)
                                                                ) or (#s602 > 0.5)
                                                              ) or (#s601 > 0.5)
                                                            ) or (#s600 > 0.5)
                                                          ) or (#s175 > 0.5)
                                                          and ((filesize > 3532872.0)
                                                            and ((#s55 <= 0.5)
                                                              and ((#s93 <= 0.5)
                                                                and ((#s119 <= 0.5)
                                                                  and ((#s100 <= 1.0)
                                                                    and ((#s307 <= 0.5)
                                                                      and ((#s1136 <= 1.0)
                                                                        and ((#s1137 > 1.0)
                                                                          and ((filesize <= 3586140.0)
                                                                          )))))))))) or (#s598 > 0.5)
                                                      ) or (#s597 > 0.5)
                                                    ) or (#s596 > 1.0)
                                                  ) or (#s595 > 1.0)
                                                ) or (#s84 > 0.5)
                                                and ((#s119 <= 0.5)
                                                  and ((#s1153 <= 0.5)
                                                    and ((#s93 <= 0.5)
                                                      and ((#s816 <= 0.5)
                                                        and ((#s52 <= 0.5)
                                                          and ((#s339 <= 0.5)
                                                            and ((#s1158 <= 1.0)
                                                              and ((#s1159 <= 0.5)
                                                                and ((#s846 <= 0.5)
                                                                  and ((#s1161 <= 1.5)
                                                                    and ((#s79 <= 1.0)
                                                                      and ((#s92 <= 0.5)
                                                                        and ((#s654 <= 1.0)
                                                                          and ((#s153 <= 0.5)
                                                                            and ((#s336 <= 0.5)
                                                                              and ((#s363 <= 1.0)
                                                                                and ((#s1168 <= 0.5)
                                                                                  and ((#s1169 <= 0.5)
                                                                                    and ((#s1170 <= 0.5)
                                                                                      and ((#s108 <= 1.0)
                                                                                        and ((#s51 > 0.5)
                                                                                          and ((#s826 <= 1.0)
                                                                                            and ((#s84 <= 1.5)
                                                                                              and ((#s87 <= 1.5)
                                                                                                and ((#s338 <= 0.5)
                                                                                                  and ((filesize <= 351736.0)
                                                                                                    and ((filesize > 228960.0)
                                                                                                    )))))))) or (#s1170 > 0.5)
                                                                                    )))) or (#s336 > 0.5)
                                                                            ))))) or (#s1161 > 1.5)
                                                                  )) or (#s1159 > 0.5)
                                                              ) or (#s1158 > 1.0)
                                                              and ((#s1200 <= 1.0)
                                                                and ((#s51 <= 0.5)
                                                                  and ((#s1202 <= 2.0)
                                                                    and ((filesize > 554298.0)
                                                                    ))))) or (#s339 > 0.5)
                                                          )) or (#s816 > 0.5)
                                                      ) or (#s93 > 0.5)
                                                      and ((#s84 <= 1.5)
                                                        and ((#s79 <= 0.5)
                                                          and ((#s78 <= 1.0)
                                                            and ((#s152 <= 0.5)
                                                              and ((#s65 <= 0.5)
                                                                and ((#s94 <= 1.0)
                                                                  and ((#s104 <= 1.0)
                                                                    and ((#s1219 <= 1.0)
                                                                      and ((#s92 <= 0.5)
                                                                        and ((#s55 <= 0.5)
                                                                          and ((#s1222 > 0.5)
                                                                            and ((filesize <= 316216.0)
                                                                            ))))))))))))) or (#s1153 > 0.5)
                                                  ))) or (#s593 > 0.5)
                                              and ((#s1239 <= 0.5)
                                                and ((#s1240 <= 0.5)
                                                  and ((#s715 <= 0.5)
                                                    and ((#s1242 <= 0.5)
                                                      and ((#s63 <= 0.5)
                                                        and ((#s1244 <= 0.5)
                                                          and ((#s55 <= 0.5)
                                                            and ((#s41 <= 1.5)
                                                            ))) or (#s63 > 0.5)
                                                        and ((#s78 <= 1.0)
                                                          and ((#s1252 > 0.5)
                                                          ))))) or (#s1240 > 0.5)
                                                ) or (#s1239 > 0.5)
                                                and ((#s1259 > 0.5)
                                                )))) or (#s18 > 0.5)
                                        ) or (#s17 > 0.5)
                                        and ((filesize <= 1348088.0)
                                          and ((#s1264 <= 0.5)
                                          ) or (filesize > 1348088.0)
                                        )) or (#s16 > 1.5)
                                      and ((#s1115 <= 1.0)
                                        and ((#s1051 <= 0.5)
                                          and ((#s73 <= 1.0)
                                            and ((#s70 <= 3.0)
                                              and ((#s1272 <= 0.5)
                                                and ((#s1273 <= 0.5)
                                                  and ((#s356 <= 1.0)
                                                    and ((#s37 <= 1.0)
                                                      and ((#s40 <= 1.0)
                                                        and ((#s331 <= 0.5)
                                                          and ((#s51 <= 0.5)
                                                            and ((#s72 <= 1.0)
                                                            )))) or (#s37 > 1.0)
                                                    ) or (#s356 > 1.0)
                                                    and ((#s119 <= 0.5)
                                                    ))))) or (#s73 > 1.0)
                                            and ((#s35 <= 0.5)
                                              and ((#s1293 > 1.0)
                                                and ((#s1069 <= 0.5)
                                                  and ((#s1296 <= 2.0)
                                                  ) or (#s1069 > 0.5)
                                                )) or (#s35 > 0.5)
                                              and ((#s1300 <= 0.5)
                                                or (#s1300 > 0.5)
                                                and ((#s1222 <= 37.5)
                                                )))) or (#s1051 > 0.5)
                                          and ((#s249 > 0.5)
                                            and ((#s1273 <= 2.0)
                                              and ((#s326 <= 0.5)
                                                and ((#s707 <= 1.0)
                                                  and ((#s851 <= 0.5)
                                                    and ((#s528 > 0.5)
                                                    )) or (#s707 > 1.0)
                                                  and ((#s1315 <= 0.5)
                                                    and ((#s63 <= 2.5)
                                                    ))) or (#s326 > 0.5)
                                                and ((#s1320 <= 2.0)
                                                  and ((#s371 <= 0.5)
                                                    and ((#s47 > 2.5)
                                                    ) or (#s371 > 0.5)
                                                    and ((#s1252 > 0.5)
                                                    )) or (#s1320 > 2.0)
                                                )) or (#s1273 > 2.0)
                                            ))) or (#s1115 > 1.0)
                                        and ((#s75 <= 6.5)
                                          and ((#s63 > 1.5)
                                            and ((#s55 <= 1.0)
                                              and ((#s1008 > 0.5)
                                                and ((#s75 <= 3.5)
                                                )))) or (#s75 > 6.5)
                                        ))) or (#s15 > 0.5)
                                  ) or (#s14 > 1.0)
                                ) or (#s13 > 0.5)
                              ) or (#s12 > 0.5)
                            ) or (#s11 > 0.5)
                            and ((#s1345 <= 1.5)
                              or (#s1345 > 1.5)
                              and ((#s708 > 1.0)
                              ))) or (#s10 > 0.5)
                          and ((#s1069 <= 0.5)
                            and ((filesize > 9026063.5)
                              and ((#s1353 <= 1.0)
                                and ((#s1168 > 2.5)
                                ) or (#s1353 > 1.0)
                              )) or (#s1069 > 0.5)
                          )) or (#s9 > 0.5)
                      ) or (#s8 > 0.5)
                    ) or (#s7 > 0.5)
                  ) or (#s6 > 2.0)
                  and ((#s62 <= 0.5)
                    and ((#s1240 <= 1.5)
                    ) or (#s62 > 0.5)
                  )) or (#s5 > 0.5)
                and ((#s1367 <= 1.5)
                  and ((#s1368 <= 0.5)
                    and ((#s1369 <= 0.5)
                      and ((#s1069 > 0.5)
                        and ((#s851 > 6.5)
                        )) or (#s1369 > 0.5)
                    ) or (#s1368 > 0.5)
                  ))) or (#s4 > 2.5)
              and ((#s1378 > 2.0)
              )) or (#s3 > 0.5)
            and ((#s92 <= 0.5)
              and ((#s160 <= 1.5)
                and ((#s1383 <= 0.5)
                  and ((#s1384 <= 0.5)
                    and ((#s173 <= 2.5)
                      and ((#s173 > 1.5)
                        and ((#s53 > 0.5)
                          and ((#s96 <= 1.0)
                            and ((#s70 <= 1.0)
                            ))))) or (#s1384 > 0.5)
                    and ((filesize <= 6480154.0)
                      and ((#s1397 <= 7.5)
                      ))) or (#s1383 > 0.5)
                ) or (#s160 > 1.5)
                and ((#s1402 <= 0.5)
                  and ((#s1384 <= 0.5)
                    and ((filesize > 1177460.0)
                      and ((filesize <= 1995768.0)
                        and ((#s1407 > 0.5)
                        ) or (filesize > 1995768.0)
                        and ((#s1115 > 1.0)
                        ))) or (#s1384 > 0.5)
                    and ((#s1413 <= 1.5)
                      and ((#s1414 <= 2.0)
                        and ((filesize > 2087332.0)
                          and ((#s103 <= 1.0)
                            and ((#s63 <= 2.0)
                            ))) or (#s1414 > 2.0)
                      ) or (#s1413 > 1.5)
                      and ((#s504 <= 1.0)
                      ))))) or (#s92 > 0.5)
              and ((#s1427 <= 0.5)
                and ((#s175 <= 0.5)
                  and ((#s1429 <= 0.5)
                    and ((#s72 <= 0.5)
                      and ((#s173 <= 2.5)
                        and ((#s485 <= 0.5)
                          and ((#s104 > 2.0)
                          ))) or (#s72 > 0.5)
                      and ((#s108 > 189.0)
                        and ((#s63 <= 1.0)
                          and ((#s1441 > 0.5)
                          )))) or (#s1429 > 0.5)
                  ) or (#s175 > 0.5)
                  and ((#s51 <= 0.5)
                    and ((#s1447 > 0.5)
                      and ((#s1449 <= 1.5)
                        or (#s1449 > 1.5)
                        and ((#s7 > 3.5)
                        ))))) or (#s1427 > 0.5)
              ))) or (#s2 > 0.5)
          and ((#s1169 <= 0.5)
            and ((#s1457 <= 0.5)
              and ((#s1458 <= 1.0)
                and ((#s1459 <= 1.0)
                  and ((#s1460 > 0.5)
                    and ((#s1462 <= 1.0)
                      and ((#s994 <= 0.5)
                        and ((#s1464 <= 0.5)
                          and ((#s354 <= 1.0)
                            and ((#s86 > 0.5)
                              and ((#s63 <= 0.5)
                                and ((filesize <= 10092017.0)
                                ) or (#s63 > 0.5)
                              )) or (#s354 > 1.0)
                          ) or (#s1464 > 0.5)
                          and ((#s1474 <= 1.0)
                            and ((#s307 > 1.0)
                            ))) or (#s994 > 0.5)
                      ) or (#s1462 > 1.0)
                      and ((#s1480 <= 1.0)
                        and ((#s102 <= 0.5)
                          and ((#s613 <= 1.0)
                            and ((#s1483 > 0.5)
                            ) or (#s613 > 1.0)
                            and ((#s1486 > 0.5)
                            )) or (#s102 > 0.5)
                        ) or (#s1480 > 1.0)
                        and ((#s89 <= 1.0)
                        )))) or (#s1459 > 1.0)
                ) or (#s1458 > 1.0)
              ) or (#s1457 > 0.5)
              and ((#s1202 > 0.5)
                and ((#s1497 <= 1.0)
                  and ((#s1498 > 2.5)
                  )))) or (#s1169 > 0.5)
            and ((#s552 > 1.0)
              and ((#s1504 <= 1.5)
                or (#s1504 > 1.5)
                and ((#s613 <= 2.0)
                  and ((filesize <= 24226160.0)
                  ) or (#s613 > 2.0)
                  and ((filesize > 25131176.0)
                  )))))) or (#s1 > 1.0)
      ) or (#s0 > 0.5)
      and ((#s1514 <= 1.5)
        and ((#s430 <= 0.5)
          and ((#s2 <= 0.5)
            and ((#s1345 <= 0.5)
              and ((#s1518 <= 0.5)
                and ((#s113 <= 1.5)
                  and ((#s1051 <= 1.5)
                    and ((#s593 <= 1.5)
                      and ((#s1522 <= 1.5)
                        and ((#s1523 <= 0.5)
                          and ((#s1369 <= 0.5)
                            and ((#s304 <= 0.5)
                              and ((#s1526 <= 0.5)
                                and ((#s510 <= 0.5)
                                  and ((#s89 <= 0.5)
                                    and ((#s63 <= 0.5)
                                      and ((#s715 <= 0.5)
                                        and ((#s86 <= 0.5)
                                          and ((#s118 > 1.0)
                                            and ((#s62 <= 0.5)
                                              and ((#s627 > 3.5)
                                              ))) or (#s86 > 0.5)
                                        )) or (#s63 > 0.5)
                                      and ((#s47 <= 3.0)
                                        and ((#s1542 <= 0.5)
                                          and ((#s1061 <= 1.5)
                                            and ((#s28 <= 0.5)
                                              and ((#s634 <= 0.5)
                                                and ((#s164 <= 1.0)
                                                  and ((#s249 > 0.5)
                                                    and ((#s1549 <= 0.5)
                                                      and ((#s1550 > 1.0)
                                                        and ((#s1552 > 0.5)
                                                          and ((#s1554 > 0.5)
                                                            and ((#s1061 <= 0.5)
                                                              and ((#s367 <= 0.5)
                                                              ) or (#s1061 > 0.5)
                                                            ))))))))) or (#s1061 > 1.5)
                                          ) or (#s1542 > 0.5)
                                        ) or (#s47 > 3.0)
                                      )) or (#s89 > 0.5)
                                    and ((#s1158 <= 1.5)
                                      and ((#s1569 > 0.5)
                                      ) or (#s1158 > 1.5)
                                    )) or (#s510 > 0.5)
                                  and ((#s1075 <= 0.5)
                                    and ((#s36 <= 0.5)
                                      and ((#s1240 <= 1.5)
                                        and ((#s1576 > 1.0)
                                        ) or (#s1240 > 1.5)
                                        and ((#s322 <= 0.5)
                                          or (#s322 > 0.5)
                                          and ((#s994 <= 0.5)
                                          )))))) or (#s1526 > 0.5)
                              ) or (#s304 > 0.5)
                              and ((#s96 <= 7.5)
                                and ((#s72 <= 2.0)
                                  and ((#s1589 <= 0.5)
                                    and ((#s16 <= 0.5)
                                      and ((#s1591 <= 0.5)
                                        and ((#s540 <= 1.0)
                                        ) or (#s1591 > 0.5)
                                      )))))) or (#s1369 > 0.5)
                          ) or (#s1523 > 0.5)
                          and ((#s108 <= 3.5)
                            and ((#s1602 > 0.5)
                              and ((#s35 <= 0.5)
                                and ((#s70 <= 1.0)
                                  and ((#s328 > 0.5)
                                  )) or (#s35 > 0.5)
                                and ((#s367 <= 0.5)
                                  and ((#s1554 <= 0.5)
                                    and ((#s1612 <= 2.0)
                                      and ((#s152 > 0.5)
                                      )))))))) or (#s1522 > 1.5)
                        and ((#s68 <= 1.0)
                          and ((#s100 <= 1.5)
                            and ((#s53 <= 0.5)
                              and ((#s1219 > 1.0)
                                and ((#s1625 <= 3.0)
                                  and ((#s118 <= 2.5)
                                    and ((#s28 <= 0.5)
                                      and ((#s995 <= 0.5)
                                        and ((#s328 > 0.5)
                                          and ((#s1631 <= 0.5)
                                            and ((#s627 <= 8.0)
                                              and ((#s510 <= 54.5)
                                                and ((#s715 > 0.5)
                                                ))) or (#s1631 > 0.5)
                                          ))) or (#s28 > 0.5)
                                      and ((#s74 > 1.0)
                                        and ((#s1643 > 0.5)
                                        ))) or (#s118 > 2.5)
                                    and ((#s1646 <= 0.5)
                                      and ((#s1647 <= 0.5)
                                        and ((#s331 <= 1.5)
                                          and ((#s103 <= 0.5)
                                            and ((filesize <= 108392.0)
                                              and ((#s73 <= 1.0)
                                                and ((#s1552 > 0.5)
                                                  and ((#s15 <= 7.5)
                                                    and ((#s1655 <= 1.0)
                                                    ) or (#s15 > 7.5)
                                                  )) or (#s73 > 1.0)
                                                and ((#s1659 > 1.5)
                                                )) or (filesize > 108392.0)
                                              and ((#s728 <= 1.5)
                                              )) or (#s103 > 0.5)
                                          ) or (#s331 > 1.5)
                                          and ((#s1462 <= 1.0)
                                            and ((filesize > 188016.0)
                                            ))) or (#s1647 > 0.5)
                                      ))) or (#s1625 > 3.0)
                                  and ((#s1673 <= 3.0)
                                    and ((filesize <= 232856.0)
                                    ) or (#s1673 > 3.0)
                                  ))) or (#s53 > 0.5)
                              and ((#s103 > 1.5)
                              )) or (#s100 > 1.5)
                            and ((#s113 <= 0.5)
                              and ((#s1682 > 0.5)
                              ) or (#s113 > 0.5)
                              and ((#s1685 <= 0.5)
                                and ((#s331 <= 0.5)
                                  and ((#s1158 > 2.0)
                                  ) or (#s331 > 0.5)
                                ) or (#s1685 > 0.5)
                              ))))) or (#s593 > 1.5)
                      and ((#s1693 <= 0.5)
                        and ((#s35 <= 0.5)
                          and ((#s57 <= 1.5)
                            and ((#s627 <= 5.0)
                              and ((#s1554 <= 0.5)
                                and ((#s63 <= 0.5)
                                ) or (#s1554 > 0.5)
                                and ((#s39 <= 1.5)
                                  and ((#s117 <= 1.0)
                                    and ((#s331 > 0.5)
                                    ) or (#s117 > 1.0)
                                  ) or (#s39 > 1.5)
                                )) or (#s627 > 5.0)
                            )) or (#s35 > 0.5)
                        ))) or (#s1051 > 1.5)
                    and ((#s65 > 0.5)
                      and ((#s64 <= 1.0)
                        and ((#s164 <= 2.5)
                          and ((#s1273 <= 0.5)
                            and ((#s1717 <= 0.5)
                            )))))) or (#s113 > 1.5)
                  and ((#s605 <= 0.5)
                    and ((#s1724 <= 0.5)
                      and ((#s1725 <= 0.5)
                        and ((#s1168 <= 0.5)
                          and ((#s70 <= 1.0)
                            and ((#s1728 > 1.0)
                              and ((#s627 > 5.5)
                                and ((filesize <= 545808.0)
                                  and ((#s829 <= 0.5)
                                    and ((#s1734 > 0.5)
                                      and ((#s328 <= 0.5)
                                        and ((#s63 > 1.0)
                                        ) or (#s328 > 0.5)
                                      )))))) or (#s70 > 1.0)
                            and ((#s1004 <= 0.5)
                              and ((#s1744 <= 0.5)
                                and ((#s111 <= 2.0)
                                  and ((#s1504 <= 0.5)
                                    and ((#s173 > 1.0)
                                    ) or (#s1504 > 0.5)
                                    and ((#s1240 <= 3.5)
                                      or (#s1240 > 3.5)
                                      and ((#s117 <= 1.0)
                                        and ((#s1273 <= 0.5)
                                        ))))) or (#s1744 > 0.5)
                              ))) or (#s1168 > 0.5)
                          and ((#s110 <= 0.5)
                          )) or (#s1725 > 0.5)
                      ) or (#s1724 > 0.5)
                    ) or (#s605 > 0.5)
                    and ((#s995 <= 0.5)
                      and ((#s510 <= 0.5)
                        and ((#s1767 <= 1.5)
                          and ((#s992 <= 0.5)
                            and ((#s89 <= 0.5)
                              and ((#s1770 <= 0.5)
                                and ((#s326 <= 0.5)
                                  and ((#s152 <= 0.5)
                                    and ((#s16 <= 1.0)
                                      and ((#s356 <= 2.0)
                                      )))) or (#s1770 > 0.5)
                                and ((#s152 > 0.5)
                                ))))) or (#s510 > 0.5)
                        and ((#s400 <= 1.0)
                          and ((#s28 > 0.5)
                            and ((#s1110 > 0.5)
                            )) or (#s400 > 1.0)
                          and ((#s1744 > 1.0)
                          ))) or (#s995 > 0.5)
                      and ((#s1244 <= 2.5)
                        and ((#s1796 <= 174.0)
                          and ((#s1115 <= 1.0)
                            and ((#s1569 <= 1.5)
                              and ((#s62 <= 0.5)
                                and ((#s1800 > 0.5)
                                ) or (#s62 > 0.5)
                                and ((#s1242 <= 0.5)
                                  or (#s1242 > 0.5)
                                  and ((#s112 > 0.5)
                                  ))) or (#s1569 > 1.5)
                              and ((#s1808 <= 0.5)
                              )))))))) or (#s1518 > 0.5)
              ) or (#s1345 > 0.5)
              and ((#s39 <= 0.5)
                and ((#s118 <= 5.0)
                  and ((#s1458 <= 1.0)
                    and ((#s1240 <= 6.5)
                      and ((#s92 <= 0.5)
                        and ((#s504 <= 0.5)
                          and ((#s851 <= 0.5)
                            and ((#s1061 <= 0.5)
                              and ((#s1823 <= 0.5)
                                or (#s1823 > 0.5)
                                and ((#s1825 > 1.5)
                                )) or (#s1061 > 0.5)
                            ) or (#s851 > 0.5)
                          )) or (#s92 > 0.5)
                        and ((#s1300 > 0.5)
                        ))))) or (#s39 > 0.5)
                and ((filesize <= 802368.0)
                  and ((#s485 <= 0.5)
                    and ((#s1839 > 1.0)
                    ) or (#s485 > 0.5)
                  ) or (filesize > 802368.0)
                  and ((#s26 <= 2.0)
                    and ((#s1844 <= 0.5)
                      and ((#s119 > 1.5)
                        and ((#s510 <= 0.5)
                        )) or (#s1844 > 0.5)
                      and ((#s1850 <= 0.5)
                      )) or (#s26 > 2.0)
                  )))) or (#s2 > 0.5)
            and ((#s1106 <= 0.5)
              and ((#s1855 <= 0.5)
              ) or (#s1106 > 0.5)
              and ((#s357 <= 2.5)
                and ((#s1859 > 0.5)
                  and ((#s326 <= 1.5)
                    and ((#s1612 > 0.5)
                      and ((#s1864 <= 1.0)
                      )))) or (#s357 > 2.5)
                and ((#s1770 > 0.5)
                )))) or (#s430 > 0.5)
          and ((#s1825 <= 3.0)
            and ((#s1462 > 1.0)
              and ((#s356 <= 0.5)
                and ((#s1875 > 4.5)
                  and ((#s1877 > 10.5)
                  )))))) or (#s1514 > 1.5)
        and ((#s1882 <= 1.0)
          and ((#s504 <= 0.5)
            and ((#s85 <= 1.0)
              and ((#s1885 > 4.5)
                and ((#s1887 <= 1.0)
                )) or (#s85 > 1.0)
              and ((#s100 <= 6.0)
                and ((#s634 <= 1.5)
                  and ((#s1612 <= 0.5)
                    and ((#s328 <= 0.5)
                      and ((#s17 <= 2.5)
                        and ((filesize <= 19809960.0)
                        ) or (#s17 > 2.5)
                      )) or (#s1612 > 0.5)
                    and ((#s108 > 59.0)
                    )) or (#s634 > 1.5)
                ) or (#s100 > 6.0)
                and ((#s608 <= 0.5)
                  and ((#s1264 <= 0.5)
                  ) or (#s608 > 0.5)
                  and ((#s1908 <= 0.5)
                  )))) or (#s504 > 0.5)
            and ((#s1052 <= 0.5)
            )) or (#s1882 > 1.0)
          and ((#s326 <= 1.0)
            and ((#s1625 <= 3.0)
              or (#s1625 > 3.0)
              and ((#s1612 <= 3.0)
              ))))))
}